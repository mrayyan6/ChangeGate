"""B2 baseline: a Trivy misconfiguration scan before every apply.

The guard scans the deployed snapshot and the pending configuration with ``trivy config`` and denies the
apply when the pending configuration has HIGH or CRITICAL findings that the deployed one does not have.
Findings are keyed by (check id, resource address), so moving code around does not create new findings.
Other actions are always allowed. Feedback uses Trivy's own title, message and resolution text.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from changegate.config import Config
from changegate.contracts import PolicyDecision, PolicyInput, Reason
from changegate.terraform import atomic_write, files_digest

SEVERITY_MAP = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "low"}


class TrivyError(RuntimeError):
    pass


class TrivyGuard:
    name = "trivy"

    def __init__(self, cfg: Config):
        self.binary = cfg.trivy.binary
        self.severities = {s.upper() for s in cfg.trivy.severities}
        self.timeout_s = cfg.trivy.timeout_s
        self.cache_dir = cfg.path(".cache/trivy")
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    # scanning

    def findings(self, files: dict[str, str]) -> dict[tuple[str, str], dict[str, Any]]:
        """Scan root module files and return findings keyed by (check id, resource)."""
        digest = files_digest(files)
        cache_file = self.cache_dir / f"{digest}.json"
        if cache_file.exists():
            raw = json.loads(cache_file.read_text(encoding="utf-8"))
        else:
            raw = self._scan(files)
            atomic_write(cache_file, json.dumps(raw))
        out: dict[tuple[str, str], dict[str, Any]] = {}
        for result in raw.get("Results") or []:
            for m in result.get("Misconfigurations") or []:
                if m.get("Status", "FAIL") != "FAIL":
                    continue
                resource = (m.get("CauseMetadata") or {}).get("Resource") or result.get("Target", "")
                out[(m.get("ID") or m.get("AVDID") or "?", resource)] = m
        return out

    def _scan(self, files: dict[str, str]) -> dict[str, Any]:
        scratch = Path(tempfile.mkdtemp(prefix="cg-trivy-"))
        try:
            for name, text in files.items():
                if name.endswith((".tf", ".tf.json", ".tfvars")):
                    (scratch / name).write_text(text, encoding="utf-8", newline="\n")
            out_file = scratch / "trivy.json"
            proc = subprocess.run(
                [self.binary, "config", "--format", "json", "--quiet", "--skip-check-update",
                 "--output", str(out_file), str(scratch)],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=self.timeout_s,
            )
            if proc.returncode != 0 or not out_file.exists():
                raise TrivyError(f"trivy exited with {proc.returncode}: {(proc.stderr or proc.stdout)[-800:]}")
            return json.loads(out_file.read_text(encoding="utf-8"))
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    # guard interface

    def decide(self, policy_input: PolicyInput, ctx) -> PolicyDecision:
        if policy_input.action != "terraform_apply":
            return PolicyDecision(decision="allow", guard=self.name, latency_ms=0.0)
        started = time.perf_counter()
        baseline = self.findings(ctx.workspace.deployed_files)
        current = self.findings(ctx.workspace.current_files())
        new = [
            (key, m)
            for key, m in sorted(current.items())
            if key not in baseline and str(m.get("Severity", "")).upper() in self.severities
        ]
        latency = (time.perf_counter() - started) * 1000
        if not new:
            return PolicyDecision(decision="allow", guard=self.name, latency_ms=latency)
        reasons = [
            Reason(
                rule_id=f"TRIVY-{key[0]}",
                policy="trivy",
                effect="deny",
                severity=SEVERITY_MAP.get(str(m.get("Severity", "")).upper(), "high"),
                resource=key[1] or None,
                message=f"{key[1]}: {m.get('Title', '')}. {m.get('Message', '')}".strip(),
                hint=str(m.get("Resolution", "") or ""),
            )
            for key, m in new
        ]
        return PolicyDecision(decision="deny", guard=self.name, reasons=reasons, latency_ms=latency)
