"""Command line interface: python -m changegate <command>.

Commands: run, eval, verify-audit, validate-scenarios, check, schemas, llm-check.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer

from changegate.config import REPO_ROOT, Config, load_config, secret

app = typer.Typer(add_completion=False, no_args_is_help=True, help="ChangeGate: policy-as-code guardrails for IaC agents.")


def _config(config: Optional[Path], overrides: Optional[list[str]], provider: Optional[str] = None,
            model: Optional[str] = None, max_steps: Optional[int] = None) -> Config:
    items = list(overrides or [])
    if provider:
        items.append(f"llm.provider={provider}")
    cfg = load_config(config, items)
    if model:
        key = "gemini.model" if cfg.llm.provider == "gemini" else "ollama.model"
        cfg = load_config(config, items + [f"llm.{key}={model}"])
    if max_steps:
        cfg.run.max_steps = max_steps
    return cfg


@app.command()
def run(
    arms: str = typer.Option("B0,B2,P", help="Comma separated arms from config (B0, B2, P, P-bare, P-reason, B1)."),
    scenario: Optional[list[str]] = typer.Option(None, "--scenario", "-s", help="Scenario id or glob; repeatable."),
    label: Optional[str] = typer.Option(None, help="Only safe or unsafe scenarios (earlier requests of their sessions are kept)."),
    category: Optional[str] = typer.Option(None, help="Only one category."),
    limit: Optional[int] = typer.Option(None, help="Run at most this many selected scenarios."),
    agent: str = typer.Option("llm", help="llm, or oracle for the scripted literal agent."),
    provider: Optional[str] = typer.Option(None, help="Override llm.provider (ollama or gemini)."),
    model: Optional[str] = typer.Option(None, help="Override the model of the chosen provider."),
    run_id: Optional[str] = typer.Option(None, help="Reuse or name a run id."),
    parallel: int = typer.Option(1, help="Run several arms at once as separate processes."),
    max_steps: Optional[int] = typer.Option(None, help="Tool calls per request."),
    config: Optional[Path] = typer.Option(None, help="Config file (default config/default.yaml)."),
    set_: Optional[list[str]] = typer.Option(None, "--set", help="Config override key.path=value; repeatable."),
):
    """Run arms over the scenarios and write raw results to results/runs/<run_id>/."""
    from changegate.runner import ArmRunner, new_run_id
    from changegate.scenarios import load_scenarios, select

    cfg = _config(config, set_, provider, model, max_steps)
    arm_names = [a.strip() for a in arms.split(",") if a.strip()]
    for name in arm_names:
        cfg.arm(name)
    all_scenarios = load_scenarios(cfg.path(cfg.run.scenarios_dir))
    chosen = select(all_scenarios, scenario, label, category, limit)
    if not chosen:
        typer.echo("No scenarios selected.")
        raise typer.Exit(2)
    run_id = run_id or new_run_id(cfg, agent)
    typer.echo(f"run {run_id}: {len(chosen)} requests x arms {', '.join(arm_names)} (agent={agent}, model={cfg.llm.model if agent == 'llm' else 'oracle'})")

    if parallel > 1 and len(arm_names) > 1:
        _run_parallel(arm_names, parallel, run_id, cfg)
        return
    for name in arm_names:
        runner = ArmRunner(cfg, run_id, name, agent)
        results = runner.run(chosen, progress=lambda line: typer.echo(line))
        passed = sum(r.assertions_passed for r in results)
        typer.echo(f"[{name}] done: {passed}/{len(results)} requests met their assertions")
    typer.echo(f"results in {(cfg.path(cfg.run.results_dir) / 'runs' / run_id).relative_to(REPO_ROOT).as_posix()}")


def _run_parallel(arm_names: list[str], parallel: int, run_id: str, cfg: Config) -> None:
    """Re-invoke this command once per arm with the same arguments, at most `parallel` at a time."""
    argv = sys.argv[1:]
    base: list[str] = []
    skip = False
    for i, token in enumerate(argv):
        if skip:
            skip = False
            continue
        if token in ("--arms", "--parallel", "--run-id"):
            skip = True
            continue
        if token.startswith(("--arms=", "--parallel=", "--run-id=")):
            continue
        base.append(token)
    out_root = cfg.path(cfg.run.results_dir) / "runs" / run_id
    pending = list(arm_names)
    running: list[tuple[str, subprocess.Popen, object]] = []
    while pending or running:
        while pending and len(running) < parallel:
            arm = pending.pop(0)
            log_path = out_root / arm / "console.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log = log_path.open("w", encoding="utf-8")
            cmd = [sys.executable, "-m", "changegate", *base, "--arms", arm, "--run-id", run_id]
            proc = subprocess.Popen(cmd, cwd=REPO_ROOT, stdout=log, stderr=subprocess.STDOUT, env=dict(os.environ, PYTHONIOENCODING="utf-8"))
            running.append((arm, proc, log))
            typer.echo(f"started arm {arm} (pid {proc.pid}), log: {log_path.relative_to(REPO_ROOT).as_posix()}")
        for item in list(running):
            arm, proc, log = item
            if proc.poll() is not None:
                log.close()
                running.remove(item)
                typer.echo(f"arm {arm} finished with exit code {proc.returncode}")
        if running:
            try:
                running[0][1].wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass


@app.command("eval")
def eval_cmd(
    run_id: Optional[list[str]] = typer.Option(None, "--run-id", help="Run id(s) to summarize; default: the latest run."),
    prefix: str = typer.Option("phase1", help="Output name prefix: results/<prefix>_summary.csv and .md"),
    config: Optional[Path] = typer.Option(None),
):
    """Compute metrics per arm and write the summary table and plots."""
    from changegate.metrics import summarize_runs

    cfg = load_config(config)
    runs_root = cfg.path(cfg.run.results_dir) / "runs"
    ids = run_id or sorted((p.name for p in runs_root.iterdir() if p.is_dir()), reverse=True)[:1]
    if not ids:
        typer.echo("No runs found under results/runs.")
        raise typer.Exit(2)
    outputs = summarize_runs(cfg, [runs_root / i for i in ids], prefix)
    for path in outputs:
        typer.echo(f"wrote {Path(path).relative_to(REPO_ROOT).as_posix()}")


@app.command("verify-audit")
def verify_audit_cmd(paths: Optional[list[Path]] = typer.Argument(None, help="Audit files or directories (default results/runs).")):
    """Verify the hash chain of audit logs."""
    from changegate.audit import verify_audit

    targets = paths or [REPO_ROOT / "results" / "runs"]
    files: list[Path] = []
    for target in targets:
        target = Path(target)
        files += [target] if target.is_file() else sorted(target.rglob("audit*.jsonl"))
    if not files:
        typer.echo("No audit logs found.")
        raise typer.Exit(2)
    failed = 0
    for path in files:
        report = verify_audit(path)
        rel = path.resolve().relative_to(REPO_ROOT).as_posix() if REPO_ROOT in path.resolve().parents else str(path)
        if report.ok:
            typer.echo(f"OK      {report.records:6d} records  {rel}")
        else:
            failed += 1
            typer.echo(f"FAILED  at seq {report.bad_seq}: {report.error}  {rel}")
    raise typer.Exit(1 if failed else 0)


@app.command("validate-scenarios")
def validate_scenarios_cmd(config: Optional[Path] = typer.Option(None), partial: bool = typer.Option(False, help="Do not require the full 40 scenario set.")):
    """Check scenario files for schema errors and twin pair consistency."""
    from changegate.scenarios import load_scenarios, validate

    cfg = load_config(config)
    scenarios = load_scenarios(cfg.path(cfg.run.scenarios_dir))
    problems = validate(scenarios, expect_full_set=not partial)
    for p in problems:
        typer.echo(f"problem: {p}")
    labels = {lab: sum(s.label == lab for s in scenarios) for lab in ("safe", "unsafe")}
    typer.echo(f"{len(scenarios)} scenarios ({labels['safe']} safe, {labels['unsafe']} unsafe), {len(problems)} problems")
    raise typer.Exit(1 if problems else 0)


def _version(cmd: list[str]) -> str:
    exe = shutil.which(cmd[0])
    if not exe:
        return "MISSING"
    try:
        out = subprocess.run([exe, *cmd[1:]], capture_output=True, text=True, timeout=60)
        return (out.stdout or out.stderr).strip().splitlines()[0]
    except (OSError, subprocess.TimeoutExpired, IndexError):
        return "installed (version unknown)"


@app.command()
def check(config: Optional[Path] = typer.Option(None)):
    """Check prerequisites and configuration (never prints secrets)."""
    cfg = load_config(config)
    rows = [
        ("python", sys.version.split()[0]),
        ("terraform", _version([cfg.terraform.binary, "version"])),
        ("opa", _version([cfg.opa.binary, "version"])),
        ("trivy", _version([cfg.trivy.binary, "--version"])),
        ("ollama", _version(["ollama", "--version"])),
        ("java (B1 only)", _version(["java", "-version"])),
        ("terraform data dir", "ok" if cfg.path(cfg.terraform.data_dir).exists() else "missing: run terraform init in envs/fintech"),
        ("llm provider", f"{cfg.llm.provider} / {cfg.llm.model}"),
        (cfg.llm.gemini.api_key_env, "set" if secret(cfg.llm.gemini.api_key_env) else "not set"),
        ("agentspec", "ready" if (REPO_ROOT / "external" / "AgentSpec" / "src").exists() else "not set up (scripts/setup_agentspec.py)"),
    ]
    for name, value in rows:
        typer.echo(f"{name:22s} {value}")


@app.command()
def schemas():
    """Export the Pydantic contracts as JSON Schema into schemas/."""
    subprocess.run([sys.executable, str(REPO_ROOT / "scripts" / "export_schemas.py")], check=True)


@app.command("llm-check")
def llm_check(provider: Optional[str] = typer.Option(None), model: Optional[str] = typer.Option(None), config: Optional[Path] = typer.Option(None)):
    """Send one small tool calling request to the configured provider."""
    from langchain_core.tools import tool

    from changegate.llm import build_chat_model

    cfg = _config(config, None, provider, model)

    @tool
    def add(a: int, b: int) -> int:
        """Add two integers."""
        return a + b

    llm = build_chat_model(cfg).bind_tools([add])
    reply = llm.invoke("Use the add tool to add 2 and 3.")
    calls = getattr(reply, "tool_calls", []) or []
    typer.echo(f"provider={cfg.llm.provider} model={cfg.llm.model} tool_calls={calls}")
    raise typer.Exit(0 if calls else 1)


def main() -> None:  # pragma: no cover
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
