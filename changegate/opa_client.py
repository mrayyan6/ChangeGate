"""Client the PEP uses to ask OPA for a decision. It fails closed: any error becomes a deny.

Two modes (``opa.mode`` in config):
    eval    one ``opa eval`` process per decision, input on stdin (simple, about 130 ms on Windows)
    server  a long lived ``opa run --server`` started on first use, queried over HTTP (a few ms)
"""

from __future__ import annotations

import atexit
import hashlib
import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from pydantic import ValidationError

from changegate.config import Config
from changegate.contracts import PolicyDecision, PolicyInput, Reason

FAIL_CLOSED_RULE = "PEP-FAIL-CLOSED"
IGNORE = ["*_test.rego", "testdata"]
DECISIONS = {"allow", "deny", "require_approval"}


class OpaError(RuntimeError):
    pass


def fail_closed_decision(error: str, latency_ms: float = 0.0, bundle_digest: str | None = None) -> PolicyDecision:
    return PolicyDecision(
        decision="deny",
        guard="fail_closed",
        latency_ms=round(latency_ms, 2),
        bundle_digest=bundle_digest,
        error=error[:500],
        reasons=[
            Reason(
                rule_id=FAIL_CLOSED_RULE,
                policy="pep",
                effect="deny",
                severity="critical",
                message="The policy engine could not evaluate this action, so it is blocked (fail closed).",
                hint="Retry the action. If it keeps failing, stop and explain the problem in submit.",
            )
        ],
    )


def parse_decision(value: Any) -> tuple[str, list[Reason]]:
    """Validate the object returned by data.changegate.main.decision. Raises OpaError when malformed."""
    if not isinstance(value, dict):
        raise OpaError(f"decision is not an object: {str(value)[:120]}")
    decision = value.get("decision")
    if decision not in DECISIONS:
        raise OpaError(f"unexpected decision value: {decision!r}")
    raw_reasons = value.get("reasons", [])
    if not isinstance(raw_reasons, list):
        raise OpaError("reasons is not a list")
    try:
        reasons = [Reason.model_validate(r) for r in raw_reasons]
    except ValidationError as exc:
        raise OpaError(f"malformed reason: {exc.errors()[0].get('msg', exc)}") from None
    if decision != "allow" and not reasons:
        raise OpaError(f"{decision} without any reason")
    return decision, reasons


class OpaClient:
    def __init__(self, cfg: Config):
        opa = cfg.opa
        self.binary = opa.binary
        self.mode = opa.mode
        self.policy_dir = cfg.path(opa.policy_dir)
        self.query = opa.query
        self.server_url = opa.server_url.rstrip("/")
        self.timeout_s = opa.timeout_s
        self._server: subprocess.Popen | None = None
        self._digest: str | None = None

    # bundle identity

    @property
    def bundle_digest(self) -> str:
        """SHA-256 over the policy files OPA loads (tests and testdata excluded)."""
        if self._digest is None:
            h = hashlib.sha256()
            files = [p for p in self.policy_dir.glob("*.rego") if not p.name.endswith("_test.rego")]
            if (self.policy_dir / "data.json").exists():
                files.append(self.policy_dir / "data.json")
            for path in sorted(files, key=lambda p: p.name):
                h.update(path.name.encode("utf-8") + b"\0" + path.read_bytes() + b"\0")
            self._digest = h.hexdigest()
        return self._digest

    # evaluation

    def evaluate(self, policy_input: PolicyInput) -> PolicyDecision:
        started = time.perf_counter()
        try:
            payload = policy_input.model_dump_json()
            value = self._eval_server(payload) if self.mode == "server" else self._eval_process(payload)
            decision, reasons = parse_decision(value)
        except Exception as exc:  # fail closed on everything
            return fail_closed_decision(f"{type(exc).__name__}: {exc}", (time.perf_counter() - started) * 1000, self._safe_digest())
        return PolicyDecision(
            decision=decision,
            reasons=reasons,
            guard="opa",
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
            bundle_digest=self._safe_digest(),
        )

    def _safe_digest(self) -> str | None:
        try:
            return self.bundle_digest
        except OSError:
            return None

    def _eval_process(self, payload: str) -> Any:
        if shutil.which(self.binary) is None and not Path(self.binary).exists():
            raise OpaError(f"opa binary not found: {self.binary}")
        cmd = [self.binary, "eval", "--format", "json", "--stdin-input"]
        for pattern in IGNORE:
            cmd += ["--ignore", pattern]
        cmd += ["-d", str(self.policy_dir), self.query]
        proc = subprocess.run(
            cmd, input=payload, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=self.timeout_s
        )
        if proc.returncode != 0:
            raise OpaError(f"opa eval exited with {proc.returncode}: {(proc.stderr or proc.stdout).strip()[:300]}")
        data = json.loads(proc.stdout)
        try:
            return data["result"][0]["expressions"][0]["value"]
        except (KeyError, IndexError, TypeError):
            raise OpaError("decision is undefined (empty result)") from None

    # server mode

    def _data_path(self) -> str:
        query = self.query.removeprefix("data.")
        return "/v1/data/" + query.replace(".", "/")

    def _healthy(self) -> bool:
        try:
            return requests.get(self.server_url + "/health", timeout=1).status_code == 200
        except requests.RequestException:
            return False

    def _ensure_server(self) -> None:
        if self._server is not None and self._server.poll() is None:
            return
        if self._healthy():
            return  # reuse a server that is already running
        url = urlparse(self.server_url)
        cmd = [self.binary, "run", "--server", "--addr", f"{url.hostname}:{url.port}"]
        for pattern in IGNORE:
            cmd += ["--ignore", pattern]
        cmd.append(str(self.policy_dir))
        self._server = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        atexit.register(self.close)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self._healthy():
                return
            if self._server.poll() is not None:
                raise OpaError(f"opa server exited with {self._server.returncode}")
            time.sleep(0.2)
        raise OpaError("opa server did not become healthy in time")

    def _eval_server(self, payload: str) -> Any:
        self._ensure_server()
        body = '{"input":' + payload + "}"
        resp = requests.post(
            self.server_url + self._data_path(), data=body.encode("utf-8"),
            headers={"Content-Type": "application/json"}, timeout=self.timeout_s,
        )
        if resp.status_code != 200:
            raise OpaError(f"opa server answered HTTP {resp.status_code}: {resp.text[:200]}")
        data = resp.json()
        if "result" not in data:
            raise OpaError("decision is undefined (no result)")
        return data["result"]

    def close(self) -> None:
        if self._server is not None and self._server.poll() is None:
            self._server.terminate()
            try:
                self._server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._server.kill()
        self._server = None
