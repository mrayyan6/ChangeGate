"""Export the Pydantic contracts in changegate/contracts.py as JSON Schema files in schemas/.

Usage (PowerShell, from the repo root):
    .\\.venv\\Scripts\\python.exe scripts\\export_schemas.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from changegate.contracts import SCHEMA_MODELS  # noqa: E402


def render(name: str) -> str:
    schema = SCHEMA_MODELS[name].model_json_schema()
    schema = {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": f"{name}.schema.json", **schema}
    return json.dumps(schema, indent=2) + "\n"


def main() -> int:
    out_dir = ROOT / "schemas"
    out_dir.mkdir(exist_ok=True)
    for name in SCHEMA_MODELS:
        path = out_dir / f"{name}.schema.json"
        path.write_text(render(name), encoding="utf-8", newline="\n")
        print(f"wrote {path.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
