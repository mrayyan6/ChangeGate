"""Hash chained audit log: chain checks, tamper detection, reopening and scripts/verify_audit.py."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from changegate.audit import GENESIS, AuditLog, VerifyReport, canonical, record_hash, verify_audit
from changegate.contracts import AuditRecord, PolicyDecision, Reason

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "verify_audit.py"
SIM_TIME = datetime(2026, 10, 17, 2, 30, tzinfo=timezone.utc)


def write_log(path: Path) -> AuditLog:
    """Four records shaped like a short P arm run."""
    log = AuditLog(path, run_id="run-1", arm="P")
    log.append("run_start", payload={"scenarios": ["SEC-01-U"]})
    decision = PolicyDecision(
        decision="deny",
        guard="opa",
        reasons=[Reason(rule_id="SEC-001", policy="security", effect="deny", message="SSH open to 0.0.0.0/0")],
    )
    log.append(
        "decision",
        request_id="SEC-01-U",
        session_id="SEC-01-U",
        sim_time=SIM_TIME,
        action="terraform_apply",
        input_digest="ab" * 32,
        payload={"decision": decision, "step": 4},
    )
    log.append("apply", request_id="SEC-01-U", session_id="SEC-01-U", sim_time=SIM_TIME, payload={"applied": False})
    log.append("run_end", payload={"status": "stopped_by_guard"})
    return log


def read_lines(path: Path) -> list[str]:
    text = path.read_bytes().decode("utf-8")
    assert text.endswith("\n")
    return text[:-1].split("\n")


def write_lines(path: Path, lines: list[str]) -> None:
    path.write_bytes("".join(line + "\n" for line in lines).encode("utf-8"))


# Writing a valid chain


def test_canonical_form_and_record_hash():
    record = {"b": [1, {"d": 2, "c": "café"}], "a": None, "hash": "ignored"}
    assert canonical(record) == '{"a":null,"b":[1,{"c":"café","d":2}],"hash":"ignored"}'
    body = '{"a":null,"b":[1,{"c":"café","d":2}]}'
    assert record_hash(record) == hashlib.sha256(body.encode("utf-8")).hexdigest()
    assert record_hash(record) == record_hash({k: v for k, v in record.items() if k != "hash"})
    assert GENESIS == "0" * 64


def test_valid_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = write_log(path)
    assert verify_audit(path) == VerifyReport(ok=True, records=4, error=None, bad_seq=None)

    lines = read_lines(path)
    records = [json.loads(line) for line in lines]
    assert [r["seq"] for r in records] == [1, 2, 3, 4]
    assert records[0]["prev_hash"] == GENESIS
    for before, after in zip(records, records[1:]):
        assert after["prev_hash"] == before["hash"]
    for line, record in zip(lines, records):
        assert line == canonical(record)
        assert record["hash"] == record_hash(record)
        AuditRecord.model_validate(record)
    assert (log.seq, log.last_hash) == (4, records[-1]["hash"])

    decision = records[1]
    assert decision["payload"]["decision"]["reasons"][0]["rule_id"] == "SEC-001"  # the model was dumped
    assert decision["sim_time"] == "2026-10-17T02:30:00Z"
    assert (decision["event"], decision["action"], decision["run_id"], decision["arm"]) == (
        "decision",
        "terraform_apply",
        "run-1",
        "P",
    )
    assert datetime.fromisoformat(decision["timestamp"]).utcoffset().total_seconds() == 0


def test_append_returns_the_stored_record(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, run_id="run-1", arm="P")
    first = log.append("run_start")
    second = log.append("decision", action="read_file", payload={"args": {"path": "main.tf"}})
    assert (first.seq, first.prev_hash, first.payload) == (1, GENESIS, {})
    assert (second.seq, second.prev_hash) == (2, first.hash)
    assert [AuditRecord.model_validate_json(line) for line in read_lines(path)] == [first, second]


def test_payload_becomes_plain_json(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, run_id="run-1", arm="B0")
    reason = Reason(rule_id="PP-001", policy="protected_paths", effect="deny", message="no edits under policies/")
    record = log.append(
        "decision",
        payload={
            "reasons": [reason, (reason,)],  # models nested in lists and tuples
            "when": SIM_TIME,
            "file": Path("policies/main.rego"),
            "tags": frozenset({"pci"}),
            7: "an int key",
            "text": "café   \ud800",  # non ASCII, a line separator JSON leaves raw, a lone surrogate
            "raw": b"\xff",
            "nan": float("nan"),
        },
    )
    assert verify_audit(path) == VerifyReport(ok=True, records=1, error=None, bad_seq=None)
    (line,) = read_lines(path)
    stored = json.loads(line)["payload"]
    assert record.payload == stored
    assert stored["reasons"][0]["rule_id"] == "PP-001" and stored["reasons"][1][0]["rule_id"] == "PP-001"
    assert stored["when"] == "2026-10-17T02:30:00Z"
    assert stored["file"] == str(Path("policies/main.rego"))
    assert stored["tags"] == ["pci"] and stored["7"] == "an int key"
    assert stored["text"] == "café   \\ud800"
    assert stored["raw"] == "b'\\xff'" and stored["nan"] is None


def test_invalid_record_is_not_written(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, run_id="run-1", arm="P")
    log.append("run_start")
    before = path.read_bytes()
    with pytest.raises(ValidationError):
        log.append("coffee_break")
    assert path.read_bytes() == before and log.seq == 1
    assert log.append("run_end").seq == 2
    assert verify_audit(path).ok


def test_empty_file_is_a_valid_log(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b"")
    assert verify_audit(path) == VerifyReport(ok=True, records=0, error=None, bad_seq=None)
    missing = verify_audit(tmp_path / "missing.jsonl")
    assert not missing.ok and missing.bad_seq is None and "cannot read" in missing.error


# Tamper detection


def edit(lines: list[str], index: int, change: Callable[[dict], None]) -> None:
    """Rewrite line ``index`` in canonical form after ``change`` mutated its record."""
    record = json.loads(lines[index])
    change(record)
    lines[index] = canonical(record)


def flip_decision(record: dict) -> None:
    record["payload"]["decision"]["decision"] = "allow"


def flip_and_rehash(record: dict) -> None:
    flip_decision(record)
    record["hash"] = record_hash(record)


def renumber(seq: int) -> Callable[[dict], None]:
    def change(record: dict) -> None:
        record["seq"] = seq
        record["hash"] = record_hash(record)

    return change


def t_payload_value(lines):  # turn the deny into an allow and keep the old hash
    edit(lines, 1, flip_decision)


def t_payload_value_rehashed(lines):  # same edit with a fresh hash: the next prev_hash gives it away
    edit(lines, 1, flip_and_rehash)


def t_hash(lines):
    edit(lines, 2, lambda record: record.update(hash="f" * 64))


def t_delete_middle(lines):
    del lines[1]


def t_delete_first(lines):
    del lines[0]


def t_swap(lines):
    lines[1], lines[2] = lines[2], lines[1]


def t_swap_renumbered(lines):  # swap, then fix seq and the hash of both records: only prev_hash is left
    lines[1], lines[2] = lines[2], lines[1]
    edit(lines, 1, renumber(2))
    edit(lines, 2, renumber(3))


def t_duplicate_line(lines):
    lines.insert(2, lines[1])


def t_truncated_line(lines):
    lines[2] = lines[2][:-10]


def t_blank_line(lines):
    lines.insert(2, "")


def t_reformatted(lines):  # same content with spaces: the hash still matches, the form does not
    lines[1] = json.dumps(json.loads(lines[1]), sort_keys=True)


def t_duplicate_key(lines):  # a reader that keeps the first key would see the forged payload
    lines[1] = '{"payload":{"forged":true},' + lines[1][1:]


TAMPERING = [
    (t_payload_value, 2, "stored hash does not match the record content"),
    (t_payload_value_rehashed, 3, "prev_hash does not match the hash of seq 2"),
    (t_hash, 3, "stored hash does not match the record content"),
    (t_delete_middle, 2, "expected seq 2, found 3"),
    (t_delete_first, 1, "expected seq 1, found 2"),
    (t_swap, 2, "expected seq 2, found 3"),
    (t_swap_renumbered, 2, "prev_hash does not match the hash of seq 1"),
    (t_duplicate_line, 3, "expected seq 3, found 2"),
    (t_truncated_line, 3, "line is not valid JSON"),
    (t_blank_line, 3, "line is blank"),
    (t_reformatted, 2, "line is not in canonical form"),
    (t_duplicate_key, 2, "duplicate key 'payload'"),
]


@pytest.mark.parametrize(("tamper", "bad_seq", "message"), TAMPERING, ids=[t[0].__name__[2:] for t in TAMPERING])
def test_tampering_is_detected(tmp_path, tamper, bad_seq, message):
    path = tmp_path / "audit.jsonl"
    write_log(path)
    lines = read_lines(path)
    tamper(lines)
    write_lines(path, lines)
    report = verify_audit(path)
    assert (report.ok, report.bad_seq, report.records) == (False, bad_seq, bad_seq - 1)
    assert message in report.error


def test_prev_hash_of_the_first_record_must_be_genesis(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_log(path)
    lines = read_lines(path)

    def change(record: dict) -> None:
        record["prev_hash"] = "1" * 64
        record["hash"] = record_hash(record)

    edit(lines, 0, change)
    write_lines(path, lines)
    assert verify_audit(path) == VerifyReport(False, 0, "prev_hash does not match GENESIS", 1)


def test_bytes_that_are_not_utf8_are_reported(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_log(path)
    raw = path.read_bytes().split(b"\n")
    raw[1] = raw[1].replace(b"SEC-001", b"SEC-\xff01")
    path.write_bytes(b"\n".join(raw))
    assert verify_audit(path) == VerifyReport(False, 1, "line is not valid UTF-8", 2)


def test_crlf_line_endings_still_verify(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_log(path)
    path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))  # what a CRLF checkout does
    assert verify_audit(path) == VerifyReport(ok=True, records=4, error=None, bad_seq=None)


def test_a_dropped_tail_shows_only_in_the_count(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = write_log(path)
    write_lines(path, read_lines(path)[:-1])
    # the chain alone cannot see missing last lines: compare the count or the last hash with a copy kept elsewhere
    report = verify_audit(path)
    assert report.ok and report.records == 3
    assert json.loads(read_lines(path)[-1])["hash"] != log.last_hash


# Reopening


def test_reopen_continues_the_chain(tmp_path):
    path = tmp_path / "runs" / "run-1" / "P" / "audit.jsonl"
    first = AuditLog(path, run_id="run-1", arm="P")
    assert path.parent.is_dir() and not path.exists()
    first.append("run_start")
    second = first.append("decision", action="read_file")

    again = AuditLog(path, run_id="run-1", arm="P")
    assert (again.seq, again.last_hash) == (2, second.hash)
    third = again.append("run_end")
    assert (third.seq, third.prev_hash) == (3, second.hash)
    assert verify_audit(path) == VerifyReport(ok=True, records=3, error=None, bad_seq=None)


def test_two_writers_on_one_file_keep_one_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    runner = AuditLog(path, run_id="run-1", arm="P")
    pep = AuditLog(path, run_id="run-1", arm="P")
    runner.append("run_start")
    pep.append("decision", action="list_files")
    pep.append("decision", action="read_file")
    runner.append("run_end")
    assert [json.loads(line)["seq"] for line in read_lines(path)] == [1, 2, 3, 4]
    assert verify_audit(path) == VerifyReport(ok=True, records=4, error=None, bad_seq=None)


def test_reopen_restores_a_lost_newline(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLog(path, run_id="run-1", arm="P").append("run_start")
    path.write_bytes(path.read_bytes().rstrip(b"\n"))
    AuditLog(path, run_id="run-1", arm="P").append("run_end")
    assert verify_audit(path) == VerifyReport(ok=True, records=2, error=None, bad_seq=None)


def test_reopen_refuses_a_damaged_last_line(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, run_id="run-1", arm="P")
    log.append("run_start")
    with path.open("ab") as f:
        f.write(b'{"seq":2,"ha')  # torn write
    with pytest.raises(ValueError, match="last line is damaged"):
        AuditLog(path, run_id="run-1", arm="P")
    with pytest.raises(ValueError, match="last line is damaged"):
        log.append("run_end")  # the open writer notices the change too and writes nothing


# scripts/verify_audit.py


def run_script(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=cwd, capture_output=True, text=True, timeout=120)


def test_script_checks_files_and_directories(tmp_path):
    runs = tmp_path / "runs" / "run-1"
    p_log, b0_log, b2_log = runs / "P" / "audit.jsonl", runs / "B0" / "audit_part2.jsonl", runs / "B2" / "audit.jsonl"
    write_log(p_log)
    write_log(b0_log)
    b2_log.parent.mkdir(parents=True)
    b2_log.write_bytes(b"")
    (runs / "P" / "runs.jsonl").write_text("not an audit log\n", encoding="utf-8")  # name does not start with audit
    (runs / "P" / "audit.txt").write_text("not jsonl\n", encoding="utf-8")

    done = run_script(str(tmp_path / "runs"), cwd=tmp_path)
    assert done.returncode == 0, done.stdout + done.stderr
    assert sorted(done.stdout.splitlines()) == sorted(
        [f"OK 4 records {p_log}", f"OK 4 records {b0_log}", f"OK 0 records {b2_log}"]
    )

    single = run_script(str(p_log), cwd=tmp_path)
    assert (single.returncode, single.stdout.splitlines()) == (0, [f"OK 4 records {p_log}"])

    lines = read_lines(b0_log)
    del lines[1]
    write_lines(b0_log, lines)
    failed = run_script(str(tmp_path / "runs"), cwd=tmp_path)
    assert failed.returncode == 1
    out = failed.stdout.splitlines()
    assert f"FAILED at seq 2: expected seq 2, found 3 {b0_log}" in out
    assert f"OK 4 records {p_log}" in out


def test_script_exit_code_2_when_nothing_is_found(tmp_path):
    (tmp_path / "empty").mkdir()
    assert run_script(str(tmp_path / "empty"), cwd=tmp_path).returncode == 2
    assert run_script(str(tmp_path / "nowhere"), cwd=tmp_path).returncode == 2
    assert run_script(cwd=tmp_path).returncode == 2


def test_script_counts_a_missing_path_as_a_failure(tmp_path):
    log = tmp_path / "audit.jsonl"
    write_log(log)
    done = run_script(str(log), str(tmp_path / "nowhere.jsonl"), cwd=tmp_path)
    assert done.returncode == 1
    assert done.stdout.splitlines() == [f"OK 4 records {log}"]
    assert "not found" in done.stderr
