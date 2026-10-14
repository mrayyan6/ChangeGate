"""Verify hash chained ChangeGate audit logs (see changegate/audit.py).

Usage (PowerShell, from the repo root):
    .\\.venv\\Scripts\\python.exe scripts\\verify_audit.py results\\runs
    .\\.venv\\Scripts\\python.exe scripts\\verify_audit.py results\\runs\\<run_id>\\P\\audit.jsonl

Each PATH is a file, or a directory that is searched for ``*.jsonl`` files whose name starts with
``audit``. Prints one line per file: ``OK <n> records <path>`` or ``FAILED at seq <n>: <error> <path>``.
Exit code 0 when every file verifies, 1 when a file fails or a PATH does not exist, 2 when no file was found.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from changegate.audit import verify_audit  # noqa: E402


def find_logs(paths: list[str]) -> tuple[list[Path], list[str]]:
    """Expand PATH arguments into audit files (each once, in order) plus the arguments that do not exist."""
    found: list[Path] = []
    missing: list[str] = []
    seen: set[Path] = set()
    for arg in paths:
        path = Path(arg)
        if path.is_file():
            candidates = [path]
        elif path.is_dir():
            candidates = sorted(p for p in path.rglob("*.jsonl") if p.name.startswith("audit") and p.is_file())
        else:
            missing.append(arg)
            continue
        for candidate in candidates:
            key = candidate.resolve()
            if key not in seen:
                seen.add(key)
                found.append(candidate)
    return found, missing


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify hash chained ChangeGate audit logs.")
    parser.add_argument("paths", nargs="+", metavar="PATH", help="an audit file, or a directory to search")
    args = parser.parse_args(argv)
    files, missing = find_logs(args.paths)
    for arg in missing:
        print(f"not found: {arg}", file=sys.stderr)
    if not files:
        print("no audit files found", file=sys.stderr)
        return 2
    failed = bool(missing)
    for path in files:
        report = verify_audit(path)
        if report.ok:
            print(f"OK {report.records} records {path}")
        else:
            failed = True
            where = f" at seq {report.bad_seq}" if report.bad_seq is not None else ""
            print(f"FAILED{where}: {report.error} {path}")
    return 1 if failed else 0


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")  # a path the console cannot encode must not crash it
    raise SystemExit(main())
