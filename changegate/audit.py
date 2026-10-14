"""Append only audit log: one JSON record per line, each holding the SHA-256 of the record above it.

Every line is ``canonical()`` of an ``AuditRecord`` dumped in JSON mode. ``hash`` is the SHA-256 of the
record without its ``hash`` key and ``prev_hash`` repeats the ``hash`` of the line above (``GENESIS`` for
the first line), so editing, deleting, inserting or reordering lines breaks the chain at that record.

Limits: the chain has no secret key and it ends wherever the file ends. Someone who can rewrite the file
can recompute every hash after an edit, and dropping the last lines leaves a shorter chain that still
verifies. Keeping ``AuditLog.last_hash`` and the record count somewhere else catches both.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from pydantic_core import to_jsonable_python

from changegate.contracts import AuditRecord

GENESIS = "0" * 64
_HEX64 = re.compile(r"[0-9a-f]{64}")


def canonical(record: dict[str, Any]) -> str:
    """The single serialization used both for hashing and for the lines of the file."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def record_hash(record: dict[str, Any]) -> str:
    """SHA-256 (hex) of ``canonical(record)`` with the ``hash`` key left out."""
    body = {key: value for key, value in record.items() if key != "hash"}
    # surrogatepass only matters for forged lines: the writer never stores lone surrogates
    return hashlib.sha256(canonical(body).encode("utf-8", "surrogatepass")).hexdigest()


# Payload normalization


def _text(value: Any) -> str:
    """``str(value)`` that can always be written as UTF-8 (lone surrogates become escapes)."""
    text = value if isinstance(value, str) else str(value)
    if text.isascii():
        return text
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        text = text.encode("utf-8", "backslashreplace").decode("utf-8")
    return text


def _clean(value: Any) -> Any:
    return _text(value) if isinstance(value, str) else value


def _jsonable(value: Any) -> Any:
    """Plain JSON data for a payload: models dumped, keys as strings, other objects as pydantic writes them."""
    if isinstance(value, BaseModel):
        try:
            value = value.model_dump(mode="json")
        except Exception:  # a field holds something pydantic cannot write as JSON: convert it below
            value = value.model_dump()
    if isinstance(value, dict):
        return {_text(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item) for item in value]
    if isinstance(value, str):
        return _text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    try:  # datetimes, paths, enums, dataclasses and so on
        return _jsonable(to_jsonable_python(value, serialize_unknown=True))
    except Exception:  # pydantic cannot convert it either, e.g. bytes that are not UTF-8
        return _text(repr(value))


# Reading lines back


def _short(value: Any, limit: int = 40) -> str:
    text = ascii(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """JSON object hook that rejects duplicate keys, so two JSON readers cannot see different records."""
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate key {_short(key)}")
        obj[key] = value
    return obj


def _parse_line(raw: bytes) -> tuple[dict[str, Any], str]:
    """Decode one line of the file into (record, text without the line ending). Raises ValueError."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("line is not valid UTF-8") from None
    text = text.removesuffix("\n").removesuffix("\r")  # a CRLF checkout changes no record
    if not text.strip():
        raise ValueError("line is blank")
    try:
        record = json.loads(text, object_pairs_hook=_unique_keys)
    except (ValueError, RecursionError) as exc:
        raise ValueError(f"line is not valid JSON ({exc})") from None
    if not isinstance(record, dict):
        raise ValueError("line is not a JSON object")
    return record, text


def _tail_record(path: Path, data: bytes) -> tuple[int, str]:
    """(seq, hash) of the last line of a non empty log. Raises ValueError when the chain cannot continue."""
    last = data.removesuffix(b"\n").rsplit(b"\n", 1)[-1]
    try:
        record, _ = _parse_line(last)
    except ValueError as exc:
        raise ValueError(f"cannot continue {path}: the last line is damaged ({exc})") from None
    seq, digest = record.get("seq"), record.get("hash")
    if type(seq) is not int or seq < 1 or not isinstance(digest, str) or not _HEX64.fullmatch(digest):
        raise ValueError(f"cannot continue {path}: the last line has no valid seq and hash")
    return seq, digest


# Writer


class AuditLog:
    """Writer for one audit file.

    Appends are serialized with a lock. Before each append the writer checks the file size, so when
    another writer (or a second instance) appended in between it continues from the new last record
    instead of forking the chain. Concurrent writers in different processes are not supported.
    """

    def __init__(self, path: str | Path, run_id: str, arm: str):
        self.path = Path(path)
        self.run_id = _text(run_id)
        self.arm = _text(arm)
        self.seq = 0  # seq of the last record in the file
        self.last_hash = GENESIS
        self._needs_newline = False
        self._size = -1  # file size after this writer's last append
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._sync()

    def _sync(self) -> None:
        """Continue from the last record in the file unless the file is exactly as this writer left it."""
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            size = 0
        if size == self._size:
            return
        data = self.path.read_bytes() if size else b""
        self.seq, self.last_hash, self._needs_newline = 0, GENESIS, False
        if data:
            self.seq, self.last_hash = _tail_record(self.path, data)
            self._needs_newline = not data.endswith(b"\n")
        self._size = len(data)

    def append(
        self,
        event: str,
        *,
        request_id: str | None = None,
        session_id: str | None = None,
        sim_time: datetime | None = None,
        action: str | None = None,
        input_digest: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> AuditRecord:
        """Write one record (flushed and fsynced) and return it exactly as stored.

        A bad event name raises pydantic's ValidationError before anything is written.
        """
        with self._lock:
            self._sync()
            record = AuditRecord(
                seq=self.seq + 1,
                timestamp=datetime.now(timezone.utc),
                sim_time=sim_time,
                run_id=self.run_id,
                arm=self.arm,
                request_id=_clean(request_id),
                session_id=_clean(session_id),
                event=event,
                action=_clean(action),
                input_digest=_clean(input_digest),
                payload=_jsonable(payload) if payload is not None else {},
                prev_hash=self.last_hash,
                hash="",  # placeholder, record_hash leaves it out
            )
            data = record.model_dump(mode="json")
            data["hash"] = record_hash(data)
            line = canonical(data) + "\n"
            with open(self.path, "a", encoding="utf-8", newline="\n") as f:
                if self._needs_newline:
                    f.write("\n")  # the last line lost its newline: never glue two records together
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
                size = os.fstat(f.fileno()).st_size
            self.seq, self.last_hash = record.seq, data["hash"]
            self._needs_newline, self._size = False, size
            return AuditRecord.model_validate(data)


# Verifier


@dataclass
class VerifyReport:
    """Result of ``verify_audit``. ``records`` counts the records that verified before any failure."""

    ok: bool
    records: int
    error: str | None
    bad_seq: int | None


def _check_line(raw: bytes, expected: int, prev: str) -> str:
    """Return the hash of line ``expected`` when it extends the chain. Raises ValueError saying why not."""
    record, text = _parse_line(raw)
    seq = record.get("seq")
    if type(seq) is not int or seq != expected:
        raise ValueError(f"expected seq {expected}, found {_short(seq)}")
    if record.get("prev_hash") != prev:
        above = "GENESIS" if expected == 1 else f"the hash of seq {expected - 1}"
        raise ValueError(f"prev_hash does not match {above}")
    if record.get("hash") != record_hash(record):
        raise ValueError("stored hash does not match the record content")
    if text != canonical(record):
        raise ValueError("line is not in canonical form")
    return record["hash"]


def verify_audit(path: str | Path) -> VerifyReport:
    """Walk the chain in ``path`` and stop at the first line that breaks it. An empty file is a valid log."""
    prev, good = GENESIS, 0
    try:
        with open(path, "rb") as f:
            for expected, raw in enumerate(f, start=1):  # binary lines split on b"\n" only
                try:
                    prev = _check_line(raw, expected, prev)
                except (ValueError, RecursionError) as exc:
                    return VerifyReport(False, good, str(exc), expected)
                good += 1
    except OSError as exc:
        return VerifyReport(False, good, f"cannot read the file ({exc.strerror or exc})", None)
    return VerifyReport(True, good, None, None)
