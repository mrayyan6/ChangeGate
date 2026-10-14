import shutil
import socket
import subprocess

import pytest

from changegate.config import load_config
from changegate.contracts import PolicyInput
from changegate.opa_client import FAIL_CLOSED_RULE, OpaClient

requires_opa = pytest.mark.skipif(shutil.which("opa") is None, reason="opa not installed")

POLICY = """package changegate.main

import rego.v1

decision := {"decision": "allow", "reasons": []} if input.action == "read_file"

decision := {"decision": "deny", "reasons": [{"rule_id": "T-1", "policy": "t", "effect": "deny",
	"severity": "high", "resource": null, "message": "no edits", "hint": "do not edit"}]} if input.action == "edit_file"

decision := {"decision": "maybe", "reasons": []} if input.action == "submit"
"""


def _input(action: str) -> PolicyInput:
    return PolicyInput.model_validate(
        {
            "action": action,
            "request": {"id": "r", "session_id": "s", "requester": "bob", "ticket": {"id": "CHG-1"},
                        "timestamp": "2026-10-17T02:30:00Z", "text": "t"},
            "session": {"session_id": "s", "window_id": "w", "window_totals": {"window_id": "w"}},
            "clock": {"now": "2026-10-17T02:30:00Z"},
        }
    )


@pytest.fixture()
def policy_dir(tmp_path):
    d = tmp_path / "policies"
    d.mkdir()
    (d / "main.rego").write_text(POLICY, encoding="utf-8")
    (d / "main_test.rego").write_text("package changegate.main_test\n", encoding="utf-8")
    return d


def _client(policy_dir, *extra):
    return OpaClient(load_config(overrides=[f"opa.policy_dir={policy_dir.as_posix()}", *extra]))


@requires_opa
def test_allow_deny_and_fail_closed_cases(policy_dir):
    client = _client(policy_dir)
    allow = client.evaluate(_input("read_file"))
    assert allow.decision == "allow" and allow.guard == "opa" and allow.latency_ms > 0
    deny = client.evaluate(_input("edit_file"))
    assert deny.decision == "deny" and deny.rule_ids == ["T-1"] and deny.reasons[0].hint == "do not edit"
    undefined = client.evaluate(_input("list_files"))
    assert undefined.decision == "deny" and undefined.guard == "fail_closed" and undefined.rule_ids == [FAIL_CLOSED_RULE]
    malformed = client.evaluate(_input("submit"))
    assert malformed.guard == "fail_closed"


def test_missing_binary_fails_closed(policy_dir):
    client = _client(policy_dir, "opa.binary=opa-does-not-exist")
    decision = client.evaluate(_input("read_file"))
    assert decision.decision == "deny" and decision.guard == "fail_closed" and "not found" in decision.error


def test_timeout_fails_closed(policy_dir, monkeypatch):
    client = _client(policy_dir)

    def boom(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="opa", timeout=1)

    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(shutil, "which", lambda name: "opa")
    assert client.evaluate(_input("read_file")).guard == "fail_closed"


def test_bundle_digest_ignores_tests(policy_dir):
    first = _client(policy_dir).bundle_digest
    (policy_dir / "main_test.rego").write_text("package changegate.main_test\n# changed\n", encoding="utf-8")
    assert _client(policy_dir).bundle_digest == first
    (policy_dir / "main.rego").write_text(POLICY + "\n# changed\n", encoding="utf-8")
    assert _client(policy_dir).bundle_digest != first


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@requires_opa
@pytest.mark.slow
def test_server_mode(policy_dir):
    client = _client(policy_dir, "opa.mode=server", f"opa.server_url=http://127.0.0.1:{_free_port()}")
    try:
        assert client.evaluate(_input("read_file")).decision == "allow"
        assert client.evaluate(_input("edit_file")).rule_ids == ["T-1"]
        assert client.evaluate(_input("list_files")).guard == "fail_closed"
    finally:
        client.close()


@requires_opa
def test_real_policies_allow_read_file():
    client = OpaClient(load_config())
    assert client.evaluate(_input("read_file")).decision == "allow"
