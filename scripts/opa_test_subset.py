"""Run `opa check --strict` and `opa test` on a subset of the policies, in an isolated copy.

Useful while several policy files are being edited: only lib.rego, data.json, testdata/ and the
named policies (plus their *_test.rego files) are loaded. Pass "all" to test the real policies/ dir.

Usage (PowerShell, from the repo root):
    .\\.venv\\Scripts\\python.exe scripts\\opa_test_subset.py security
    .\\.venv\\Scripts\\python.exe scripts\\opa_test_subset.py blast_radius cumulative
    .\\.venv\\Scripts\\python.exe scripts\\opa_test_subset.py all
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
POLICIES = ROOT / "policies"


def run(cmd: list[str]) -> int:
    print("$", " ".join(cmd), flush=True)
    return subprocess.run(cmd).returncode


def main(names: list[str]) -> int:
    if not names:
        print(__doc__)
        return 2
    if names == ["all"]:
        rc = run(["opa", "check", "--strict", str(POLICIES)])
        return rc or run(["opa", "test", str(POLICIES), "-v"])
    tmp_root = Path(tempfile.mkdtemp(prefix="opa-subset-"))
    target = tmp_root / "policies"
    target.mkdir()
    try:
        shutil.copy2(POLICIES / "lib.rego", target)
        shutil.copy2(POLICIES / "data.json", target)
        if (POLICIES / "testdata").exists():
            shutil.copytree(POLICIES / "testdata", target / "testdata")
        for name in names:
            for suffix in (".rego", "_test.rego"):
                src = POLICIES / f"{name}{suffix}"
                if src.exists():
                    shutil.copy2(src, target)
                elif suffix == ".rego":
                    print(f"missing policy file: {src}")
                    return 2
        rc = run(["opa", "check", "--strict", str(target)])
        return rc or run(["opa", "test", str(target), "-v"])
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
