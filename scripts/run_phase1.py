"""Run the whole Phase 1 experiment and build the summary table.

Arms run in two lanes at the same time; inside a lane the arms run one after another:
    lane 1: B0, B2, B1 (B1 only when AgentSpec is set up)
    lane 2: P, then the G3 ablations P-reason and P-bare on the unsafe requests
Every step uses --resume, so running the script again after an interruption continues where it stopped:
finished sessions are skipped, and cached LLM responses and plans make repeated work cheap.
Progress goes to results/runs/<run_id>/driver.log and to one console.log per arm.

Usage (PowerShell, from the repo root):
    .\\.venv\\Scripts\\python.exe scripts\\run_phase1.py --run-id phase1-llama31
    .\\.venv\\Scripts\\python.exe scripts\\run_phase1.py --run-id phase1-gemini --provider gemini
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENTSPEC_PARSER = ROOT / "external" / "AgentSpec" / "src" / "spec_lang" / "AgentSpecParser.py"
AGENTSPEC_GRAMMAR = ROOT / "external" / "AgentSpec" / "src" / "spec_lang" / "AgentSpec.g4"

LANES = [
    [("B0", None), ("B2", None), ("B1", None)],
    [("P", None), ("P-reason", "unsafe"), ("P-bare", "unsafe")],
]
# With one lane the core comparison runs first. One lane is the default for a local Ollama model: Ollama
# serves one request at a time, and two interleaved conversations evict each other's cached prompt prefix.
SINGLE_LANE = [("B0", None), ("P", None), ("B2", None), ("B1", None), ("P-reason", "unsafe"), ("P-bare", "unsafe")]


def agentspec_ready() -> bool:
    # ANTLR serializes grammar literals into a binary ATN array, not plain text, so the predicate
    # names never appear in the generated AgentSpecParser.py. Check the patched grammar source instead
    # (which setup_agentspec.py writes) plus that the parser was regenerated after it.
    if not (AGENTSPEC_PARSER.exists() and AGENTSPEC_GRAMMAR.exists()):
        return False
    if "cg_public_ingress" not in AGENTSPEC_GRAMMAR.read_text(encoding="utf-8", errors="ignore"):
        return False
    return AGENTSPEC_PARSER.stat().st_mtime >= AGENTSPEC_GRAMMAR.stat().st_mtime


class Driver:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.out = ROOT / "results" / "runs" / args.run_id
        self.out.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()

    def log(self, message: str) -> None:
        line = f"{datetime.now():%Y-%m-%d %H:%M:%S} {message}"
        with self.lock:
            with (self.out / "driver.log").open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            print(line, flush=True)

    def command(self, arm: str, label: str | None) -> list[str]:
        cmd = [sys.executable, "-m", "changegate", "run", "--arms", arm, "--run-id", self.args.run_id, "--resume"]
        if label:
            cmd += ["--label", label]
        if self.args.provider:
            cmd += ["--provider", self.args.provider]
        if self.args.model:
            cmd += ["--model", self.args.model]
        for item in self.args.set or []:
            cmd += ["--set", item]
        return cmd

    def run_lane(self, lane: list[tuple[str, str | None]]) -> None:
        for arm, label in lane:
            if arm == "B1" and not agentspec_ready():
                self.log("B1 skipped: AgentSpec is not set up (run scripts/setup_agentspec.py)")
                continue
            log_path = self.out / arm / "console.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            self.log(f"{arm} started" + (f" ({label} requests)" if label else ""))
            env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
            with log_path.open("a", encoding="utf-8") as fh:
                rc = subprocess.run(self.command(arm, label), cwd=ROOT, stdout=fh, stderr=subprocess.STDOUT, env=env).returncode
            self.log(f"{arm} finished with exit code {rc}")

    def run(self) -> int:
        self.log(f"driver started (pid {os.getpid()}), run id {self.args.run_id}")
        lanes = LANES if self.args.lanes > 1 else [SINGLE_LANE]
        threads = [threading.Thread(target=self.run_lane, args=(lane,)) for lane in lanes]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        rc = subprocess.run(
            [sys.executable, "-m", "changegate", "eval", "--run-id", self.args.run_id, "--prefix", self.args.prefix],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.log(f"eval finished with exit code {rc.returncode}: {(rc.stdout or rc.stderr).strip()[-500:]}")
        self.log("driver done")
        return rc.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--provider", default=None)
    parser.add_argument("--model", default=None)
    parser.add_argument("--lanes", type=int, default=1, help="2 runs two arms at once (useful for an API model)")
    parser.add_argument("--prefix", default="phase1", help="summary file prefix")
    parser.add_argument("--set", action="append", help="config override key.path=value")
    return Driver(parser.parse_args()).run()


if __name__ == "__main__":
    raise SystemExit(main())
