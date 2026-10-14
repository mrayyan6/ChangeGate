"""Set up AgentSpec (the base paper's runtime enforcement framework) for the B1 baseline.

AgentSpec has no license file, so its code is never copied into this repository. This script:
1. makes a blobless, sparse clone of https://github.com/haoyuwang99/AgentSpec at a pinned commit into
   external/AgentSpec (gitignored), checking out only src/ and the dependency files;
2. appends the ChangeGate predicate names to the PREDICATE token of AgentSpec's ANTLR grammar, because
   AgentSpec only accepts predicate names listed in its grammar;
3. regenerates the Python lexer and parser with the ANTLR jar that ships in the AgentSpec repo (needs Java);
4. checks that the rules in baselines/agentspec_rules/changegate.spec parse.

Usage (PowerShell, from the repo root; needs git and Java 11+):
    .\\.venv\\Scripts\\python.exe scripts\\setup_agentspec.py
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

URL = "https://github.com/haoyuwang99/AgentSpec"
COMMIT = "e6fa3902e2cfb9681f454b355691b771f70543f8"
DEST = ROOT / "external" / "AgentSpec"
SPARSE = ["/src/", "/pyproject.toml", "/requirement.txt", "/README.md"]


def run(cmd: list[str], cwd: Path | None = None) -> str:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"command failed: {' '.join(cmd)}\n{proc.stderr or proc.stdout}")
    return proc.stdout


def clone() -> None:
    if not (DEST / ".git").exists():
        DEST.parent.mkdir(parents=True, exist_ok=True)
        run(["git", "clone", "--filter=blob:none", "--no-checkout", "--quiet", URL, str(DEST)])
    run(["git", "sparse-checkout", "set", "--no-cone", *SPARSE], cwd=DEST)
    run(["git", "checkout", "--quiet", "--force", COMMIT], cwd=DEST)
    head = run(["git", "rev-parse", "HEAD"], cwd=DEST).strip()
    if head != COMMIT:
        raise SystemExit(f"expected {COMMIT}, got {head}")
    print(f"AgentSpec at {head[:12]} in {DEST.relative_to(ROOT).as_posix()}")


def patch_grammar() -> bool:
    from baselines.agentspec_predicates import PREDICATE_NAMES

    grammar = DEST / "src" / "spec_lang" / "AgentSpec.g4"
    text = grammar.read_text(encoding="utf-8")
    match = re.search(r"PREDICATE:(.*?);", text, re.DOTALL)
    if not match:
        raise SystemExit("PREDICATE token not found in the AgentSpec grammar")
    existing = set(re.findall(r"'([^']+)'", match.group(1)))
    missing = [name for name in PREDICATE_NAMES if name not in existing]
    if not missing:
        print("grammar already lists the ChangeGate predicates")
        return False
    addition = "".join(f" | '{name}'" for name in missing)
    patched = text[: match.end(1)] + addition + " " + text[match.end(1):]
    grammar.write_text(patched, encoding="utf-8")
    print(f"added {len(missing)} predicates to the grammar")
    return True


def regenerate() -> None:
    java = shutil.which("java")
    if java is None:
        raise SystemExit("Java is needed to regenerate the AgentSpec parser (install a JDK 11 or newer)")
    spec_lang = DEST / "src" / "spec_lang"
    jar = spec_lang / "antlr-4.13.2-complete.jar"
    run([java, "-jar", str(jar), "-Dlanguage=Python3", "AgentSpec.g4"], cwd=spec_lang)
    print("regenerated the AgentSpec lexer and parser")


def check_rules() -> None:
    from baselines.agentspec_arm import load_rules

    rules = load_rules()
    print(f"parsed {len(rules)} AgentSpec rules: {', '.join(r.id for r in rules)}")


def main() -> int:
    clone()
    if patch_grammar() or not (DEST / "src" / "spec_lang" / "AgentSpecParser.py").exists():
        regenerate()
    check_rules()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
