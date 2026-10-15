"""Export runs into the skill-creator eval-viewer layout and build a static HTML review.

For every arm and request this writes <workspace>/<arm>/<request>/ with
    eval_metadata.json      {"eval_id", "prompt"}
    outputs/transcript.md   the agent's tool calls, the gate's decisions and the observations
    grading.json            the end state assertions as graded expectations, shaped like the grading.json
                            schema in skill-creator's references/schemas.md
and then runs skill-creator's eval-viewer/generate_review.py --static to produce one HTML file.

Usage (PowerShell, from the repo root):
    .\\.venv\\Scripts\\python.exe scripts\\export_review.py --run-id phase1-llama31
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from changegate.contracts import Assertion, RunResult  # noqa: E402
from changegate.metrics import load_results  # noqa: E402


def find_viewer() -> Path | None:
    for base in (Path.home() / ".claude" / "plugins", Path.home() / ".claude" / "skills"):
        for path in sorted(base.glob("**/skill-creator/eval-viewer/generate_review.py")):
            return path
    return None


def describe(a: Assertion) -> str:
    parts = [a.type]
    for name in ("address", "sg", "path", "port", "cidr", "value", "max", "present"):
        value = getattr(a, name)
        if value is not None:
            parts.append(f"{name}={value}")
    if a.addresses:
        parts.append("addresses=" + ",".join(a.addresses))
    text = " ".join(str(p) for p in parts)
    return f"{text} ({a.note})" if a.note else text


def transcript_md(r: RunResult, transcript: dict) -> str:
    lines = ["## Eval Prompt", "", transcript.get("request", ""), "", "## Run", ""]
    lines += [
        f"* arm: {r.arm} (guard {r.guard}, feedback {r.feedback_mode}), model {r.model}",
        f"* label: {r.label}, category: {r.category}",
        f"* status: {r.status}, steps: {r.steps}, applies: {r.applies}, wall time: {r.wall_time_s}s",
        f"* decisions: {r.decision_counts}, rules cited: {', '.join(r.denied_rule_ids) or 'none'}",
        "",
        "## Gate decisions",
        "",
    ]
    for call in r.tool_calls:
        rules = f" {','.join(call.rule_ids)}" if call.rule_ids else ""
        lines.append(f"{call.step}. {call.tool} -> {call.decision}{rules} (guard {call.guard})")
    lines += ["", "## Transcript", ""]
    for event in transcript.get("events", []):
        if "tool" in event:
            args = json.dumps(event.get("args", {}), ensure_ascii=False)
            lines.append(f"**{event['tool']}** `{args[:600]}`")
            lines.append("")
            lines.append("```")
            lines.append(str(event.get("observation", ""))[:1500])
            lines.append("```")
        elif "user" in event:
            lines.append(f"**user:** {event['user']}")
        elif "assistant" in event:
            lines.append(f"**assistant:** {event['assistant']}")
        elif "error" in event:
            lines.append(f"**error:** {event['error']}")
        lines.append("")
    return "\n".join(lines)


def grading(r: RunResult) -> dict:
    expectations = [
        {"text": describe(a.assertion), "passed": a.passed, "evidence": a.detail} for a in r.assertions
    ]
    for a in r.compliant_assertions or []:
        expectations.append({"text": "compliant: " + describe(a.assertion), "passed": a.passed, "evidence": a.detail})
    passed = sum(e["passed"] for e in expectations)
    tools = Counter(call.tool for call in r.tool_calls)
    return {
        "expectations": expectations,
        "summary": {"passed": passed, "failed": len(expectations) - passed, "total": len(expectations),
                    "pass_rate": round(passed / len(expectations), 2) if expectations else 0.0},
        "execution_metrics": {"tool_calls": dict(tools), "total_tool_calls": sum(tools.values()),
                              "total_steps": r.steps, "errors_encountered": int(r.status == "error")},
        "timing": {"executor_duration_seconds": r.wall_time_s, "total_duration_seconds": r.wall_time_s},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run-id", action="append", required=True)
    parser.add_argument("--out", default="results/phase1_review.html")
    args = parser.parse_args()

    run_dirs = [ROOT / "results" / "runs" / rid for rid in args.run_id]
    results = sorted(load_results(run_dirs), key=lambda r: (r.scenario_id, r.arm))
    workspace = ROOT / "work" / "review" / "-".join(args.run_id)
    shutil.rmtree(workspace, ignore_errors=True)
    order = {sid: i for i, sid in enumerate(sorted({r.scenario_id for r in results}))}
    for r in results:
        run_dir = workspace / r.arm / r.scenario_id
        (run_dir / "outputs").mkdir(parents=True, exist_ok=True)
        transcript_path = next((d / r.arm / "transcripts" / f"{r.scenario_id}.json" for d in run_dirs
                                if (d / r.arm / "transcripts" / f"{r.scenario_id}.json").exists()), None)
        transcript = json.loads(transcript_path.read_text(encoding="utf-8")) if transcript_path else {}
        (run_dir / "eval_metadata.json").write_text(
            json.dumps({"eval_id": order[r.scenario_id], "prompt": transcript.get("request", r.scenario_id)}), encoding="utf-8")
        (run_dir / "outputs" / "transcript.md").write_text(transcript_md(r, transcript), encoding="utf-8")
        (run_dir / "grading.json").write_text(json.dumps(grading(r), indent=1), encoding="utf-8")
    print(f"exported {len(results)} runs to {workspace.relative_to(ROOT).as_posix()}")

    viewer = find_viewer()
    if viewer is None:
        print("skill-creator eval-viewer not found; the exported workspace can still be opened by hand")
        return 0
    out = ROOT / args.out
    proc = subprocess.run([sys.executable, str(viewer), str(workspace), "--skill-name", "ChangeGate Phase 1",
                           "--static", str(out)], capture_output=True, text=True, encoding="utf-8", errors="replace")
    print((proc.stdout or proc.stderr).strip())
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
