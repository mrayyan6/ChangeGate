"""SQLite session store: cumulative changes per change window, applied changes and approvals.

A change window id is the start of the most recent weekly change window at or before a time, in UTC.
With the default Saturday 02:00 window, every time from Saturday 2026-10-17 02:00 up to Saturday
2026-10-24 01:59 belongs to ``2026-10-17T02:00Z``. Each window is one budget period, so deletes split
across several requests of a session still add up against the same per window limits.

Tables::

    sessions    one row per session id
    requests    request ids seen per session, each recorded once
    applies     one row per apply that changed something: window, time, digest, counts, addresses
    approvals   Approval models as JSON, in insertion order

Window totals are sums over the ``applies`` rows of one session and window, so they can never drift
from the rows they summarize.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any

from changegate.contracts import Approval, ChangeSet, SessionState, WindowTotals

WINDOW_ID_FORMAT = "%Y-%m-%dT%H:%MZ"
WEEKDAYS = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")
MEMORY = ":memory:"

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS requests (
    seq INTEGER PRIMARY KEY,
    session_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    UNIQUE (session_id, request_id)
);
CREATE TABLE IF NOT EXISTS applies (
    seq INTEGER PRIMARY KEY,
    session_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    window_id TEXT NOT NULL,
    ts TEXT NOT NULL,
    changeset_digest TEXT NOT NULL,
    creates INTEGER NOT NULL,
    updates INTEGER NOT NULL,
    deletes INTEGER NOT NULL,
    changes INTEGER NOT NULL,
    addresses TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS applies_by_window ON applies (session_id, window_id);
CREATE TABLE IF NOT EXISTS approvals (
    seq INTEGER PRIMARY KEY,
    session_id TEXT NOT NULL,
    approval_id TEXT NOT NULL,
    approval TEXT NOT NULL,
    UNIQUE (session_id, approval_id)
);
"""

APPLY_COLUMNS = (
    "session_id, request_id, window_id, ts, changeset_digest, creates, updates, deletes, changes, addresses"
)


# change windows


def _as_utc(ts: datetime) -> datetime:
    """``ts`` converted to UTC; a naive datetime is taken to be UTC already."""
    if ts.tzinfo is None or ts.utcoffset() is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def _weekday_index(name: str) -> int:
    """Monday is 0, as in ``datetime.weekday()``. Accepts full or three letter names, any case."""
    key = str(name).strip().lower()
    for index, day in enumerate(WEEKDAYS):
        if key in (day, day[:3]):
            return index
    raise ValueError(f"unknown weekday '{name}', expected a day name such as Saturday")


def _start_time(text: str) -> time:
    match = re.fullmatch(r"([0-9]{1,2}):([0-9]{2})", str(text).strip())
    if match is None or int(match[1]) > 23 or int(match[2]) > 59:
        raise ValueError(f"window start must be HH:MM in 24 hour time, got '{text}'")
    return time(int(match[1]), int(match[2]))


def _window_start(ts: datetime, weekday: int, start: time) -> datetime:
    now = _as_utc(ts)
    day = now.date() - timedelta(days=(now.weekday() - weekday) % 7)
    begin = datetime.combine(day, start, tzinfo=timezone.utc)
    if begin > now:  # it is the window weekday, but before the window opens
        begin -= timedelta(days=7)
    return begin


def window_id(ts: datetime, weekday: str = "Saturday", start: str = "02:00") -> str:
    """Start of the most recent change window at or before ``ts``, in UTC, e.g. ``2026-10-17T02:00Z``."""
    return _window_start(ts, _weekday_index(weekday), _start_time(start)).strftime(WINDOW_ID_FORMAT)


def _counts(changeset: ChangeSet) -> tuple[int, int, int]:
    """Create, update and delete counts from the summary.

    A ChangeSet built without its summary still lists its changes, so those are counted instead of
    recording zeros for a real apply.
    """
    s = changeset.summary
    if s.total == 0 and changeset.changes:
        actions = [c.action for c in changeset.changes]
        return actions.count("create"), actions.count("update"), actions.count("delete")
    return s.create, s.update, s.delete


def _ensure(db: sqlite3.Connection, session_id: str) -> None:
    db.execute("INSERT OR IGNORE INTO sessions (session_id) VALUES (?)", (session_id,))


# store


class SessionStore:
    """Per session change totals by window, applied changes and approvals, kept in one SQLite file."""

    def __init__(self, path: str | Path, weekday: str = "Saturday", start: str = "02:00"):
        # Parse the window first so a bad config fails before any file is created.
        self._weekday = _weekday_index(weekday)
        self._start = _start_time(start)
        self.weekday = weekday
        self.start = start
        self.path = Path(path)
        if str(path) != MEMORY:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        # One connection shared by all threads; the lock keeps each transaction in one piece.
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False, timeout=30)
        self._conn.row_factory = sqlite3.Row
        try:
            self._conn.executescript(SCHEMA)
            self._conn.commit()
        except sqlite3.Error:  # e.g. the path is not a SQLite file: do not leave it open
            self._conn.close()
            raise

    def __enter__(self) -> SessionStore:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the database. Closing twice is harmless; any later call raises."""
        with self._lock:
            self._conn.close()

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        """One locked transaction: committed when the block succeeds, rolled back when it raises."""
        with self._lock, self._conn:
            yield self._conn

    def window_id(self, ts: datetime) -> str:
        """Change window id of ``ts`` under this store's weekday and start time."""
        return _window_start(ts, self._weekday, self._start).strftime(WINDOW_ID_FORMAT)

    # writes

    def ensure_session(self, session_id: str) -> None:
        """Register the session id. record_request, add_approval and a non empty record_apply do this too."""
        with self._write() as db:
            _ensure(db, session_id)

    def record_request(self, session_id: str, request_id: str) -> None:
        """Count ``request_id`` as seen in the session. Recording it again changes nothing."""
        with self._write() as db:
            _ensure(db, session_id)
            db.execute(
                "INSERT OR IGNORE INTO requests (session_id, request_id) VALUES (?, ?)", (session_id, request_id)
            )

    def record_apply(self, session_id: str, request_id: str, ts: datetime, changeset: ChangeSet) -> WindowTotals:
        """Add an applied ChangeSet to the totals of the window of ``ts`` and return the new totals.

        A ChangeSet with no changes records nothing and the current totals come back unchanged.
        """
        wid = self.window_id(ts)
        creates, updates, deletes = _counts(changeset)
        changes = creates + updates + deletes
        with self._lock:
            if changes:
                addresses = json.dumps([c.address for c in changeset.changes])
                row = (session_id, request_id, wid, _as_utc(ts).isoformat(), changeset.digest)
                with self._write() as db:
                    _ensure(db, session_id)
                    db.execute(
                        f"INSERT INTO applies ({APPLY_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (*row, creates, updates, deletes, changes, addresses),
                    )
            return self._totals(session_id, wid)

    def add_approval(self, session_id: str, approval: Approval) -> None:
        """Store ``approval``. One with the same approval_id is replaced where it stands in the order."""
        with self._write() as db:
            _ensure(db, session_id)
            db.execute(
                "INSERT INTO approvals (session_id, approval_id, approval) VALUES (?, ?, ?)"
                " ON CONFLICT (session_id, approval_id) DO UPDATE SET approval = excluded.approval",
                (session_id, approval.approval_id, approval.model_dump_json()),
            )

    # reads

    def _totals(self, session_id: str, wid: str) -> WindowTotals:
        creates, updates, deletes, changes, applies = self._conn.execute(
            "SELECT COALESCE(SUM(creates), 0), COALESCE(SUM(updates), 0), COALESCE(SUM(deletes), 0),"
            " COALESCE(SUM(changes), 0), COUNT(*) FROM applies WHERE session_id = ? AND window_id = ?",
            (session_id, wid),
        ).fetchone()
        return WindowTotals(
            window_id=wid, creates=creates, updates=updates, deletes=deletes, changes=changes, applies=applies
        )

    def window_totals(self, session_id: str, window_id: str) -> WindowTotals:
        """Totals of one window of the session; all zeros when nothing was applied in it."""
        with self._lock:
            return self._totals(session_id, window_id)

    def approvals(self, session_id: str) -> list[Approval]:
        """Every approval of the session, in insertion order."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT approval FROM approvals WHERE session_id = ? ORDER BY seq", (session_id,)
            ).fetchall()
        return [Approval.model_validate_json(row["approval"]) for row in rows]

    def snapshot(self, session_id: str, ts: datetime) -> SessionState:
        """Session state for a request at ``ts``: its window totals, all approvals and the request count."""
        wid = self.window_id(ts)
        with self._lock:
            totals = self._totals(session_id, wid)
            approvals = self.approvals(session_id)
            (seen,) = self._conn.execute(
                "SELECT COUNT(*) FROM requests WHERE session_id = ?", (session_id,)
            ).fetchone()
        return SessionState(
            session_id=session_id, window_id=wid, window_totals=totals, approvals=approvals, requests_seen=seen
        )

    def applied_changes(self, session_id: str) -> list[dict[str, Any]]:
        """Every recorded apply of the session, oldest first. ``ts`` is the stored UTC ISO string."""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {APPLY_COLUMNS} FROM applies WHERE session_id = ? ORDER BY seq", (session_id,)
            ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["addresses"] = json.loads(item["addresses"])
            out.append(item)
        return out
