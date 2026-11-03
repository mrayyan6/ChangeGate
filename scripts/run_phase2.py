"""Run the Phase 2 test-set experiments one after another, in priority order, and resume after any stop.

Each job is one `changegate run` call on the test split. Finished sessions are skipped (--resume), so the
script is safe to start again after an interruption. Jobs run one at a time because the local GPU is shared.
Usage:  python scripts/run_phase2.py [--split test] [--prefix p2-test]
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

ABLATIONS = "P-nocum,P-nosod,P-nocw,P-nopp,P-nobr,P-nostore"


def jobs() -> list[tuple[int, str, list[str]]]:
    """(seed, arms, extra args), highest priority first."""
    plan: list[tuple[int, str, list[str]]] = []
    for seed in (1, 2, 3):
        plan.append((seed, "B0,P", []))
    plan.append((1, "B2", []))
    plan.append((1, "B1", []))
    plan.append((1, "P-reason,P-bare", ["--label", "unsafe"]))
    plan.append((1, ABLATIONS, []))
    for seed in (2, 3):
        plan.append((seed, "B2", []))
        plan.append((seed, "B1", []))
    for seed in (2, 3):
        plan.append((seed, "P-reason,P-bare", ["--label", "unsafe"]))
    for seed in (2, 3):
        plan.append((seed, ABLATIONS, []))
    return plan


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split", default="test")
    parser.add_argument("--prefix", default="p2-test")
    args = parser.parse_args()
    py = ROOT / ".venv" / "Scripts" / "python.exe"
    log = ROOT / ".cache" / f"{args.prefix}-driver.log"
    log.parent.mkdir(exist_ok=True)
    with log.open("a", encoding="utf-8") as fh:
        for seed, arms, extra in jobs():
            run_id = f"{args.prefix}-s{seed}"
            cmd = [str(py), "-u", "-m", "changegate", "run", "--arms", arms, "--split", args.split,
                   "--run-id", run_id, "--resume", "--set", f"run.seed={seed}", *extra]
            fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} START {run_id} {arms} {' '.join(extra)}\n")
            fh.flush()
            code = subprocess.call(cmd, cwd=ROOT, stdout=fh, stderr=subprocess.STDOUT)
            fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} END {run_id} {arms} exit {code}\n")
            fh.flush()


if __name__ == "__main__":
    sys.exit(main())
