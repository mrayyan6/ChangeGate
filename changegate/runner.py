"""Run one arm over a list of scenarios and write raw results.

Output layout:
    results/runs/<run_id>/<arm>/runs.jsonl        one RunResult per request
    results/runs/<run_id>/<arm>/audit.jsonl       hash chained audit log of every decision
    results/runs/<run_id>/<arm>/sessions.sqlite   session store (cumulative changes, approvals)
    results/runs/<run_id>/<arm>/transcripts/      one JSON transcript per request
    work/<run_id>/<arm>/<session_id>/             the agent's sandbox repo and deployed state
"""

from __future__ import annotations

import json
import re
import shutil
import statistics
import subprocess
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from changegate.agent import AgentOutcome, request_message, run_llm_agent, run_oracle_agent
from changegate.approvals import ApprovalSimulator
from changegate.audit import AuditLog
from changegate.config import REPO_ROOT, Config
from changegate.contracts import LatencyStats, RunResult, Scenario
from changegate.evaluator import all_passed, evaluate_assertions
from changegate.feedback import FeedbackComposer
from changegate.pep import PEP, NoGuard, OpaGuard
from changegate.plan_diff import state_digest
from changegate.runtime import RunContext
from changegate.scenarios import group_sessions
from changegate.session_store import SessionStore
from changegate.terraform import TerraformRunner
from changegate.tools import ToolExecutor, build_tools
from changegate.workspace import Workspace


def slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-")


def new_run_id(cfg: Config, agent_kind: str) -> str:
    model = cfg.llm.model if agent_kind == "llm" else "oracle"
    return f"{datetime.now():%Y%m%d-%H%M%S}-{slug(model)}"


def git_commit() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True)
        return out.stdout.strip() or "unknown"
    except OSError:
        return "unknown"


def change_window_params(cfg: Config) -> tuple[str, str]:
    data = json.loads((cfg.path(cfg.opa.policy_dir) / "data.json").read_text(encoding="utf-8"))
    window = data["changegate"]["params"]["change_window"]
    return window["weekday"], window["start"]


def make_guard(kind: str, cfg: Config):
    if kind == "none" or kind == "agentspec":
        return NoGuard()  # AgentSpec enforces inside its own executor
    if kind == "opa":
        from changegate.opa_client import OpaClient

        return OpaGuard(OpaClient(cfg))
    if kind == "trivy":
        from baselines.trivy_guard import TrivyGuard

        return TrivyGuard(cfg)
    raise ValueError(f"unknown guard {kind}")


def latency_stats(values: list[float]) -> LatencyStats:
    if not values:
        return LatencyStats()
    return LatencyStats(
        n=len(values),
        mean_ms=round(statistics.fmean(values), 2),
        p50_ms=round(statistics.median(values), 2),
        max_ms=round(max(values), 2),
    )


class ArmRunner:
    def __init__(self, cfg: Config, run_id: str, arm_name: str, agent_kind: str = "llm"):
        self.cfg = cfg
        self.run_id = run_id
        self.arm_name = arm_name
        self.arm = cfg.arm(arm_name)
        self.agent_kind = agent_kind
        self.out_dir = cfg.path(cfg.run.results_dir) / "runs" / run_id / arm_name
        self.work_dir = cfg.path(cfg.run.work_dir) / run_id / arm_name
        self.out_dir.mkdir(parents=True, exist_ok=True)
        (self.out_dir / "transcripts").mkdir(exist_ok=True)
        weekday, start = change_window_params(cfg)
        self.store = SessionStore(self.out_dir / "sessions.sqlite", weekday=weekday, start=start)
        self.audit = AuditLog(self.out_dir / "audit.jsonl", run_id, arm_name)
        self.guard = make_guard(self.arm.guard, cfg)
        self.feedback = FeedbackComposer(self.arm.feedback)
        self.approvals = ApprovalSimulator([cfg.agent.id])
        self.terraform = TerraformRunner(cfg)
        self.llm = None
        self.cache = None
        self.tracker = None
        if agent_kind == "llm":
            from changegate.llm import UsageTracker, build_chat_model, install_cache

            self.cache = install_cache(cfg)
            self.llm = build_chat_model(cfg)
            self.tracker = UsageTracker()

    def write_meta(self, scenarios: list[Scenario]) -> None:
        meta = {
            "run_id": self.run_id,
            "arm": self.arm_name,
            "guard": self.arm.guard,
            "feedback": self.arm.feedback,
            "agent": self.agent_kind,
            "provider": self.cfg.llm.provider if self.agent_kind == "llm" else "none",
            "model": self.cfg.llm.model if self.agent_kind == "llm" else "oracle",
            "temperature": self.cfg.llm.temperature,
            "seed": self.cfg.run.seed,
            "max_steps": self.cfg.run.max_steps,
            "scenarios": [s.id for s in scenarios],
            "git_commit": git_commit(),
            "started": datetime.now(timezone.utc).isoformat(),
        }
        (self.out_dir / "arm_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    def run(self, scenarios: list[Scenario], progress=print) -> list[RunResult]:
        self.write_meta(scenarios)
        results: list[RunResult] = []
        try:
            for session_id, members in group_sessions(scenarios):
                # A session always starts from the pristine env and an empty session record.
                dest = self.work_dir / slug(session_id)
                if dest.exists():
                    shutil.rmtree(dest)
                self.store.reset_session(session_id)
                ws = Workspace.create(
                    self.cfg.path(self.cfg.terraform.env_dir), dest, self.terraform, members[0].workspace_patches
                )
                for sc in members:
                    result = self.run_one(sc, ws)
                    results.append(result)
                    with (self.out_dir / "runs.jsonl").open("a", encoding="utf-8", newline="\n") as fh:
                        fh.write(result.model_dump_json() + "\n")
                    verdict = "PASS" if result.assertions_passed else "FAIL"
                    progress(
                        f"[{self.arm_name}] {sc.id:14s} {sc.label:6s} {result.status:24s} assertions={verdict} "
                        f"denies={result.decision_counts.get('deny', 0)} steps={result.steps} {result.wall_time_s:.0f}s"
                    )
        finally:
            close = getattr(getattr(self.guard, "client", None), "close", None)
            if callable(close):
                close()
        return results

    def run_one(self, sc: Scenario, ws: Workspace) -> RunResult:
        cfg = self.cfg
        request = sc.to_change_request()
        self.store.ensure_session(sc.session_id)
        self.store.record_request(sc.session_id, sc.id)
        ctx = RunContext(
            cfg=cfg,
            run_id=self.run_id,
            arm=self.arm_name,
            scenario=sc,
            request=request,
            workspace=ws,
            store=self.store,
            approvals=self.approvals,
            audit=self.audit,
            agent_id=cfg.agent.id,
        )
        pep = PEP(ctx, self.guard, self.feedback, ToolExecutor(ctx))
        self.audit.append(
            "run_start", request_id=sc.id, session_id=sc.session_id, sim_time=request.timestamp,
            payload={"arm": self.arm_name, "agent": self.agent_kind, "request": request.model_dump(mode="json")},
        )
        hits_before = self.cache.hits if self.cache else 0
        if self.tracker:
            self.tracker.reset()
        started = time.perf_counter()
        error = None
        try:
            if self.agent_kind == "oracle":
                outcome = run_oracle_agent(ctx, pep)
            elif self.arm.guard == "agentspec":
                from baselines.agentspec_arm import run_agentspec_agent

                outcome = run_agentspec_agent(ctx, self.llm, pep, cfg.run.max_steps, [self.tracker])
            else:
                outcome = run_llm_agent(ctx, self.llm, build_tools(pep), cfg.run.max_steps, [self.tracker])
        except Exception as exc:  # the run is recorded as an error, the experiment continues
            error = f"{type(exc).__name__}: {exc}"
            ctx.transcript.append({"error": error, "traceback": traceback.format_exc()[-4000:]})
            outcome = AgentOutcome("error", ctx.step, "", error)
        wall = time.perf_counter() - started

        final = ws.deployed
        assertions = evaluate_assertions(sc.assertions, final, ws.initial)
        compliant = evaluate_assertions(sc.compliant_assertions, final, ws.initial) if sc.compliant_assertions else None
        counts: dict[str, int] = {"allow": 0, "deny": 0, "require_approval": 0}
        denied: list[str] = []
        for rec in ctx.records:
            counts[rec.decision] = counts.get(rec.decision, 0) + 1
            if rec.decision != "allow":
                denied.extend(rec.rule_ids)
        usage = None
        cost = 0.0
        if self.tracker:
            from changegate.llm import cost_usd

            usage = self.tracker.usage(cache_hits=(self.cache.hits - hits_before) if self.cache else 0)
            cost = cost_usd(cfg, usage)
        result = RunResult(
            run_id=self.run_id,
            arm=self.arm_name,
            agent=self.agent_kind,
            provider=cfg.llm.provider if self.agent_kind == "llm" else "none",
            model=cfg.llm.model if self.agent_kind == "llm" else "oracle",
            seed=cfg.run.seed,
            guard=self.arm.guard,
            feedback_mode=self.arm.feedback,
            scenario_id=sc.id,
            twin_id=sc.twin_id,
            session_id=sc.session_id,
            category=sc.category,
            label=sc.label,
            status=outcome.status if outcome.status in ("submitted", "finished_without_submit", "max_steps", "stopped_by_guard", "error") else "error",
            summary=ctx.summary or outcome.final_output[:500],
            steps=outcome.steps,
            tool_calls=ctx.records,
            decision_counts=counts,
            denied_rule_ids=sorted(set(denied)),
            approvals_requested=ctx.approvals_requested,
            approvals_granted=ctx.approvals_granted,
            applies=ctx.applies,
            cost_usd=cost,
            decision_latency=latency_stats(ctx.decision_latencies),
            wall_time_s=round(wall, 2),
            changeset_sources=dict(ctx.changeset_sources),
            assertions=assertions,
            assertions_passed=all_passed(assertions),
            compliant_assertions=compliant,
            compliant_passed=all_passed(compliant) if compliant is not None else None,
            final_state_digest=state_digest(final),
            error=error or outcome.error,
        )
        if usage is not None:
            result.tokens = usage
        self.audit.append(
            "run_end", request_id=sc.id, session_id=sc.session_id, sim_time=request.timestamp,
            payload={"status": result.status, "assertions_passed": result.assertions_passed,
                     "compliant_passed": result.compliant_passed, "applies": result.applies},
        )
        transcript: dict[str, Any] = {
            "scenario_id": sc.id,
            "arm": self.arm_name,
            "request": request_message(request),
            "status": result.status,
            "events": ctx.transcript,
            "tool_calls": [r.model_dump(mode="json") for r in ctx.records],
            "assertions": [a.model_dump(mode="json") for a in assertions],
        }
        (self.out_dir / "transcripts" / f"{slug(sc.id)}.json").write_text(
            json.dumps(transcript, indent=1, default=str), encoding="utf-8"
        )
        return result
