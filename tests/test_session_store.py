from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import pytest

from changegate.contracts import Approval, ChangeSet, ChangeSummary, ResourceChange, SessionState, WindowTotals
from changegate.session_store import SessionStore, window_id

UTC = timezone.utc
PKT = timezone(timedelta(hours=5))
EST = timezone(timedelta(hours=-5))
SAT = datetime(2026, 10, 17, 2, 30, tzinfo=UTC)  # inside the Saturday change window
W1 = "2026-10-17T02:00Z"
W2 = "2026-10-24T02:00Z"


def _cs(tag: str, create: int = 0, update: int = 0, delete: int = 0, summary: bool = True) -> ChangeSet:
    """ChangeSet with the given number of creates, updates and deletes on made up buckets."""
    changes = []
    for action, count in (("create", create), ("update", update), ("delete", delete)):
        for i in range(count):
            name = f"{tag}_{action}_{i}"
            address = f"aws_s3_bucket.{name}"
            changes.append(ResourceChange(address=address, type="aws_s3_bucket", name=name, action=action))
    return ChangeSet(
        source="plan",
        changes=changes,
        summary=ChangeSummary(create=create, update=update, delete=delete) if summary else ChangeSummary(),
        base_digest=f"{tag}-base",
        target_digest=f"{tag}-target",
        digest=f"{tag}-digest",
    )


def _approval(approval_id: str, **overrides) -> Approval:
    data = {
        "approval_id": approval_id,
        "request_id": "R1",
        "ticket_id": "CHG-1",
        "requester": "bob",
        "approver": "alice",
        "granted": True,
        "reason": "resize the core database",
        "changeset_digest": "r1-digest",
        "timestamp": SAT,
    }
    data.update(overrides)
    return Approval(**data)


@pytest.fixture
def store(tmp_path):
    s = SessionStore(tmp_path / "session.sqlite")
    yield s
    s.close()


# window ids


@pytest.mark.parametrize(
    ("ts", "expected"),
    [
        (datetime(2026, 10, 17, 2, 0, tzinfo=UTC), W1),  # the window opens
        (datetime(2026, 10, 17, 1, 59, 59, 999999, tzinfo=UTC), "2026-10-10T02:00Z"),  # just before it opens
        (datetime(2026, 10, 17, 2, 30, tzinfo=UTC), W1),
        (datetime(2026, 10, 17, 4, 0, tzinfo=UTC), W1),  # after the approval free hours, same budget week
        (datetime(2026, 10, 18, 12, 0, tzinfo=UTC), W1),  # Sunday
        (datetime(2026, 10, 14, 15, 0, tzinfo=UTC), "2026-10-10T02:00Z"),  # Wednesday
        (datetime(2026, 10, 23, 23, 59, tzinfo=UTC), W1),  # Friday night
        (datetime(2026, 10, 24, 1, 59, tzinfo=UTC), W1),
        (datetime(2026, 10, 24, 2, 0, tzinfo=UTC), W2),
        (datetime(2027, 1, 1, 10, 0, tzinfo=UTC), "2026-12-26T02:00Z"),  # across a year boundary
        (datetime(2026, 3, 1, 0, 0, tzinfo=UTC), "2026-02-28T02:00Z"),  # across a month boundary
        (datetime(2026, 10, 17, 2, 30), W1),  # naive means UTC
        (datetime(2026, 10, 17, 6, 30, tzinfo=PKT), "2026-10-10T02:00Z"),  # 01:30 UTC
        (datetime(2026, 10, 17, 7, 0, tzinfo=PKT), W1),  # 02:00 UTC
        (datetime(2026, 10, 16, 22, 0, tzinfo=EST), W1),  # Friday locally, Saturday 03:00 UTC
    ],
)
def test_window_id_examples(ts, expected):
    assert window_id(ts) == expected


def test_window_id_sweep_over_three_weeks():
    """Every timestamp maps to the latest Saturday 02:00 UTC at or before it."""
    ts, end = datetime(2026, 10, 3, tzinfo=UTC), datetime(2026, 10, 25, tzinfo=UTC)
    seen = set()
    while ts < end:
        wid = window_id(ts)
        begin = datetime.strptime(wid, "%Y-%m-%dT%H:%MZ").replace(tzinfo=UTC)
        assert begin.weekday() == 5 and (begin.hour, begin.minute) == (2, 0)
        assert begin <= ts < begin + timedelta(days=7)
        assert window_id(ts.astimezone(PKT)) == window_id(ts.replace(tzinfo=None)) == wid
        seen.add(wid)
        ts += timedelta(minutes=37)
    assert seen == {"2026-09-26T02:00Z", "2026-10-03T02:00Z", "2026-10-10T02:00Z", W1, W2}


def test_window_id_custom_weekday_and_start():
    wed = datetime(2026, 10, 14, 15, 0, tzinfo=UTC)
    assert window_id(wed, "Wednesday", "14:30") == "2026-10-14T14:30Z"
    assert window_id(wed, "wednesday", "15:01") == "2026-10-07T15:01Z"
    assert window_id(wed, "Sat", "2:00") == "2026-10-10T02:00Z"
    assert window_id(datetime(2026, 10, 18, 0, 0, tzinfo=UTC), "Sunday", "00:00") == "2026-10-18T00:00Z"


@pytest.mark.parametrize(
    ("weekday", "start"), [("Caturday", "02:00"), ("Saturday", "24:00"), ("Saturday", "2am"), ("Saturday", "02:60")]
)
def test_bad_window_config_is_rejected(tmp_path, weekday, start):
    with pytest.raises(ValueError):
        window_id(SAT, weekday, start)
    with pytest.raises(ValueError):
        SessionStore(tmp_path / "bad" / "session.sqlite", weekday, start)
    assert not (tmp_path / "bad").exists()


def test_store_uses_its_configured_window(tmp_path):
    wed = datetime(2026, 10, 14, 15, 0, tzinfo=UTC)
    with SessionStore(tmp_path / "session.sqlite", weekday="Wednesday", start="14:00") as store:
        assert store.window_id(wed) == "2026-10-14T14:00Z"
        assert store.record_apply("S1", "R1", wed, _cs("a", update=1)).window_id == "2026-10-14T14:00Z"
        assert store.snapshot("S1", wed).window_totals.updates == 1
    with SessionStore(tmp_path / "default.sqlite") as store:
        assert store.window_id(wed) == window_id(wed) == "2026-10-10T02:00Z"


# totals


def test_cumulative_totals_across_two_requests_in_one_window(store):
    """Two requests in one window add up: this is what catches a split change."""
    store.record_request("S1", "R1")
    first = store.record_apply("S1", "R1", SAT, _cs("r1", update=1, delete=2))
    assert first == WindowTotals(window_id=W1, updates=1, deletes=2, changes=3, applies=1)
    store.record_request("S1", "R2")
    second = store.record_apply("S1", "R2", SAT + timedelta(hours=30), _cs("r2", create=1, delete=2))
    assert second == WindowTotals(window_id=W1, creates=1, updates=1, deletes=4, changes=6, applies=2)
    assert store.window_totals("S1", W1) == second


def test_windows_and_sessions_are_separate(store):
    store.record_apply("S1", "R1", SAT, _cs("a", delete=3))
    store.record_apply("S1", "R2", datetime(2026, 10, 24, 1, 59, tzinfo=UTC), _cs("b", delete=1))  # still W1
    store.record_apply("S1", "R3", datetime(2026, 10, 24, 2, 0, tzinfo=UTC), _cs("c", delete=2))  # next week
    store.record_apply("S2", "R4", SAT, _cs("d", create=5))
    assert store.window_totals("S1", W1) == WindowTotals(window_id=W1, deletes=4, changes=4, applies=2)
    assert store.window_totals("S1", W2) == WindowTotals(window_id=W2, deletes=2, changes=2, applies=1)
    assert store.window_totals("S2", W1) == WindowTotals(window_id=W1, creates=5, changes=5, applies=1)
    assert store.window_totals("S2", W2) == WindowTotals(window_id=W2)
    assert store.window_totals("unknown", W1) == WindowTotals(window_id=W1)


def test_empty_changeset_records_nothing(store):
    store.record_apply("S1", "R1", SAT, _cs("a", update=1))
    assert store.record_apply("S1", "R2", SAT, _cs("noop")) == WindowTotals(
        window_id=W1, updates=1, changes=1, applies=1
    )
    assert store.record_apply("S1", "R3", SAT + timedelta(days=7), _cs("noop")) == WindowTotals(window_id=W2)
    assert [row["request_id"] for row in store.applied_changes("S1")] == ["R1"]


def test_changeset_without_summary_is_counted_from_its_changes(store):
    totals = store.record_apply("S1", "R1", SAT, _cs("a", create=1, delete=2, summary=False))
    assert (totals.creates, totals.deletes, totals.changes, totals.applies) == (1, 2, 3, 1)


def test_applied_changes_rows(store):
    store.record_apply("S1", "R1", datetime(2026, 10, 17, 2, 30), _cs("r1", create=1, delete=1))
    store.record_apply("S1", "R2", datetime(2026, 10, 17, 8, 15, tzinfo=PKT), _cs("r2", update=1))
    first, second = store.applied_changes("S1")
    assert first == {
        "session_id": "S1",
        "request_id": "R1",
        "window_id": W1,
        "ts": "2026-10-17T02:30:00+00:00",
        "changeset_digest": "r1-digest",
        "creates": 1,
        "updates": 0,
        "deletes": 1,
        "changes": 2,
        "addresses": ["aws_s3_bucket.r1_create_0", "aws_s3_bucket.r1_delete_0"],
    }
    assert second["ts"] == "2026-10-17T03:15:00+00:00" and second["addresses"] == ["aws_s3_bucket.r2_update_0"]
    assert store.applied_changes("S2") == []


def test_concurrent_applies_from_threads(store):
    def worker(n: int) -> None:
        for i in range(10):
            store.record_apply("S1", f"T{n}-{i}", SAT, _cs(f"t{n}_{i}", delete=1))

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    totals = store.window_totals("S1", W1)
    assert (totals.deletes, totals.changes, totals.applies) == (40, 40, 40)
    assert len(store.applied_changes("S1")) == 40


# approvals, requests and snapshots


def test_approvals_round_trip_and_replace(store):
    rejected = _approval("APR-1", granted=False, approver="bob", reason="self approval")
    other = _approval("APR-2", request_id="R2", approver=None, timestamp=datetime(2026, 10, 17, 9, 0, tzinfo=PKT))
    store.add_approval("S1", rejected)
    store.add_approval("S1", other)
    assert store.approvals("S1") == [rejected, other]
    assert store.approvals("S1")[1].timestamp == datetime(2026, 10, 17, 4, 0, tzinfo=UTC)

    granted = rejected.model_copy(update={"granted": True, "approver": "alice", "detail": "second look"})
    store.add_approval("S1", granted)
    assert store.approvals("S1") == [granted, other]  # replaced where it stood
    assert store.approvals("S2") == []


def test_ensure_session_and_writes_register_the_session(tmp_path):
    path = tmp_path / "session.sqlite"
    with SessionStore(path) as store:
        store.ensure_session("S1")
        store.ensure_session("S1")
        store.record_request("S2", "R1")
        store.add_approval("S3", _approval("APR-1"))
        store.record_apply("S4", "R2", SAT, _cs("a", update=1))
        store.record_apply("S5", "R3", SAT, _cs("noop"))  # records nothing at all
        assert store.snapshot("S1", SAT).requests_seen == 0
    con = sqlite3.connect(path)
    try:
        ids = [row[0] for row in con.execute("SELECT session_id FROM sessions ORDER BY session_id")]
    finally:
        con.close()
    assert ids == ["S1", "S2", "S3", "S4"]


def test_snapshot_content(store):
    for request_id in ("R1", "R2", "R1"):  # recording is idempotent per request id
        store.record_request("S1", request_id)
    store.record_request("S2", "R1")
    store.record_apply("S1", "R1", SAT, _cs("r1", delete=2))
    approval = _approval("APR-1")
    store.add_approval("S1", approval)

    snap = store.snapshot("S1", SAT + timedelta(hours=1))
    assert snap == SessionState(
        session_id="S1",
        window_id=W1,
        window_totals=WindowTotals(window_id=W1, deletes=2, changes=2, applies=1),
        approvals=[approval],
        requests_seen=2,
    )
    assert SessionState.model_validate_json(snap.model_dump_json()) == snap

    later = store.snapshot("S1", SAT + timedelta(days=7))
    assert later.window_id == W2 and later.window_totals == WindowTotals(window_id=W2)
    assert later.approvals == [approval] and later.requests_seen == 2
    assert store.snapshot("S2", SAT).requests_seen == 1
    assert store.snapshot("unknown", SAT) == SessionState(
        session_id="unknown", window_id=W1, window_totals=WindowTotals(window_id=W1)
    )


# persistence


def test_persists_after_reopening(tmp_path):
    path = tmp_path / "nested" / "dir" / "session.sqlite"
    store = SessionStore(path)
    assert path.exists()
    store.record_request("S1", "R1")
    store.record_apply("S1", "R1", SAT, _cs("r1", delete=2))
    store.add_approval("S1", _approval("APR-1"))
    store.close()
    store.close()  # closing twice is harmless
    with pytest.raises(sqlite3.ProgrammingError):
        store.window_totals("S1", W1)

    with SessionStore(path) as again:
        snap = again.snapshot("S1", SAT)
        assert snap.window_totals == WindowTotals(window_id=W1, deletes=2, changes=2, applies=1)
        assert snap.requests_seen == 1 and [a.approval_id for a in snap.approvals] == ["APR-1"]
        assert [row["changeset_digest"] for row in again.applied_changes("S1")] == ["r1-digest"]
        again.record_request("S1", "R1")
        again.record_request("S1", "R2")
        totals = again.record_apply("S1", "R2", SAT + timedelta(hours=2), _cs("r2", delete=2))
        assert (totals.deletes, totals.applies) == (4, 2)
    with SessionStore(path) as third:
        assert third.snapshot("S1", SAT).requests_seen == 2
        assert third.window_totals("S1", W1).deletes == 4


def test_not_a_database_fails_without_holding_the_file(tmp_path):
    path = tmp_path / "session.sqlite"
    path.write_text("this is not a sqlite file, " * 100, encoding="utf-8")
    with pytest.raises(sqlite3.DatabaseError) as excinfo:
        SessionStore(path)
    # excinfo keeps the half built store alive, so only an explicit close frees the file. On Windows
    # unlink fails while a connection still holds it.
    path.unlink()
    assert "not a database" in str(excinfo.value)


def test_in_memory_store():
    with SessionStore(":memory:") as store:
        assert store.record_apply("S1", "R1", SAT, _cs("a", delete=1)).deletes == 1
        assert store.snapshot("S1", SAT).window_totals.applies == 1
