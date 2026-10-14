"""Offline Terraform runner with a content addressed plan cache.

Every plan runs in a scratch copy of the root module files so the agent's workspace never collects
plan artifacts. All copies share one initialized ``TF_DATA_DIR`` (the env's ``.terraform``), so no
per-workspace ``terraform init`` is needed. Results are cached by a SHA-256 of the file contents.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from changegate.config import Config

# Files Terraform reads from a root module directory.
TF_SUFFIXES = (".tf", ".tf.json", ".tfvars", ".tfvars.json")
LOCK_FILE = ".terraform.lock.hcl"
CACHE_FORMAT = 1


def is_tf_file(name: str) -> bool:
    return name == LOCK_FILE or name.endswith(TF_SUFFIXES)


def read_text(path: Path) -> str:
    """Read a text file as UTF-8, dropping a BOM and normalizing line endings to LF."""
    return path.read_text(encoding="utf-8-sig").replace("\r\n", "\n")


def root_module_files(root: Path) -> dict[str, str]:
    """Return the root module files of ``root`` (top level only), keyed by file name."""
    files: dict[str, str] = {}
    for entry in sorted(root.iterdir()):
        if entry.is_file() and is_tf_file(entry.name):
            files[entry.name] = read_text(entry)
    return files


def files_digest(files: dict[str, str]) -> str:
    h = hashlib.sha256()
    for name in sorted(files):
        h.update(name.encode("utf-8") + b"\0" + files[name].encode("utf-8") + b"\0")
    return h.hexdigest()


@dataclass
class PlanOutcome:
    ok: bool
    digest: str
    plan: dict[str, Any] | None = None
    error: str | None = None
    elapsed_ms: float = 0.0
    cached: bool = False
    transient: bool = False  # timeouts and tool crashes are not cached


def _trim_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Keep only what the ChangeSet builder needs, so cache files stay small."""
    changes = [
        {
            "address": rc.get("address"),
            "mode": rc.get("mode"),
            "type": rc.get("type"),
            "name": rc.get("name"),
            "after_unknown": (rc.get("change") or {}).get("after_unknown") or {},
        }
        for rc in plan.get("resource_changes", [])
    ]

    def trim_config(module: dict[str, Any]) -> dict[str, Any]:
        out = {
            "resources": [
                {"address": r.get("address"), "mode": r.get("mode"), "expressions": r.get("expressions", {})}
                for r in module.get("resources", [])
            ]
        }
        calls = module.get("module_calls") or {}
        if calls:
            out["module_calls"] = {
                name: {"module": trim_config(call.get("module") or {})} for name, call in calls.items()
            }
        return out

    return {
        "format_version": plan.get("format_version"),
        "terraform_version": plan.get("terraform_version"),
        "planned_values": plan.get("planned_values", {}),
        "resource_changes": changes,
        "configuration": {"root_module": trim_config((plan.get("configuration") or {}).get("root_module") or {})},
    }


class TerraformRunner:
    def __init__(self, cfg: Config):
        tf = cfg.terraform
        self.binary = tf.binary
        self.data_dir = cfg.path(tf.data_dir)
        self.plugin_cache_dir = cfg.path(tf.plugin_cache_dir)
        self.cache_dir = cfg.path(tf.plan_cache_dir)
        self.timeout_s = tf.timeout_s
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def env(self) -> dict[str, str]:
        env = dict(os.environ)
        env.update(
            {
                "TF_DATA_DIR": str(self.data_dir),
                "TF_PLUGIN_CACHE_DIR": str(self.plugin_cache_dir),
                "TF_IN_AUTOMATION": "1",
                "TF_INPUT": "0",
                "CHECKPOINT_DISABLE": "1",
            }
        )
        return env

    def _cache_path(self, digest: str) -> Path:
        return self.cache_dir / f"{digest}.json"

    def plan(self, files: dict[str, str]) -> PlanOutcome:
        digest = files_digest(files)
        cache_file = self._cache_path(digest)
        if cache_file.exists():
            try:
                cached = json.loads(cache_file.read_text(encoding="utf-8"))
                if cached.get("cache_format") == CACHE_FORMAT:
                    return PlanOutcome(
                        ok=cached["ok"],
                        digest=digest,
                        plan=cached.get("plan"),
                        error=cached.get("error"),
                        elapsed_ms=cached.get("elapsed_ms", 0.0),
                        cached=True,
                    )
            except (OSError, ValueError, KeyError):
                pass  # corrupt cache entry: recompute below
        outcome = self._run_plan(files, digest)
        if outcome.transient:
            return outcome
        payload = {
            "cache_format": CACHE_FORMAT,
            "ok": outcome.ok,
            "plan": outcome.plan,
            "error": outcome.error,
            "elapsed_ms": outcome.elapsed_ms,
        }
        tmp = cache_file.with_suffix(f".{uuid.uuid4().hex}.tmp")
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        os.replace(tmp, cache_file)
        return outcome

    def _run(self, args: list[str], cwd: Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            [self.binary, *args],
            cwd=cwd,
            env=self.env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self.timeout_s,
        )

    def _run_plan(self, files: dict[str, str], digest: str) -> PlanOutcome:
        started = time.perf_counter()
        scratch = self.cache_dir / "tmp" / f"{digest[:16]}-{uuid.uuid4().hex[:8]}"
        scratch.mkdir(parents=True, exist_ok=True)
        try:
            for name, text in files.items():
                (scratch / name).write_text(text, encoding="utf-8", newline="\n")
            plan_args = ["plan", "-refresh=false", "-input=false", "-lock=false", "-no-color", "-out=tfplan"]
            proc = self._run(plan_args, scratch)
            if proc.returncode != 0:
                return PlanOutcome(
                    ok=False,
                    digest=digest,
                    error=_tail((proc.stderr or "") + (proc.stdout or "")),
                    elapsed_ms=(time.perf_counter() - started) * 1000,
                )
            show = self._run(["show", "-json", "tfplan"], scratch)
            if show.returncode != 0:
                return PlanOutcome(
                    ok=False,
                    digest=digest,
                    error="terraform show failed: " + _tail(show.stderr or show.stdout or ""),
                    elapsed_ms=(time.perf_counter() - started) * 1000,
                    transient=True,
                )
            plan = _trim_plan(json.loads(show.stdout))
            return PlanOutcome(ok=True, digest=digest, plan=plan, elapsed_ms=(time.perf_counter() - started) * 1000)
        except subprocess.TimeoutExpired:
            return PlanOutcome(
                ok=False,
                digest=digest,
                error=f"terraform timed out after {self.timeout_s}s",
                elapsed_ms=(time.perf_counter() - started) * 1000,
                transient=True,
            )
        finally:
            shutil.rmtree(scratch, ignore_errors=True)


def _tail(text: str, limit: int = 3000) -> str:
    text = text.strip()
    return text if len(text) <= limit else "..." + text[-limit:]
