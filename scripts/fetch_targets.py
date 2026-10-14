"""Env B (Phase 2): fetch the public vulnerable-by-design Terraform repos into targets/ at pinned commits.

targets/ is gitignored. Clones are blobless, so only the files of the pinned commit are downloaded.

Usage (PowerShell, from the repo root):
    .\\.venv\\Scripts\\python.exe scripts\\fetch_targets.py            # fetch both
    .\\.venv\\Scripts\\python.exe scripts\\fetch_targets.py terragoat  # fetch one
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGETS = {
    "terragoat": ("https://github.com/bridgecrewio/terragoat.git", "729f8da"),
    "kaimonkey": ("https://github.com/accurics/KaiMonkey.git", "3feb0bf"),
}


def git(*args: str, cwd: Path | None = None) -> str:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def fetch(name: str) -> Path:
    url, commit = TARGETS[name]
    dest = ROOT / "targets" / name
    if not (dest / ".git").exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        git("clone", "--filter=blob:none", "--no-checkout", "--quiet", url, str(dest))
    git("checkout", "--quiet", "--detach", commit, cwd=dest)
    head = git("rev-parse", "HEAD", cwd=dest)
    if not head.startswith(commit):
        raise RuntimeError(f"{name}: expected commit {commit}, got {head}")
    print(f"{name}: {url} at {head} -> {dest.relative_to(ROOT).as_posix()}")
    return dest


def main(argv: list[str]) -> int:
    names = argv or list(TARGETS)
    unknown = [n for n in names if n not in TARGETS]
    if unknown:
        print(f"unknown target(s): {', '.join(unknown)}; choose from {', '.join(TARGETS)}")
        return 2
    for name in names:
        fetch(name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
