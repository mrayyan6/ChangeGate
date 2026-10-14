"""Policy Enforcement Point: the single wrapper every tool call passes through.

For each proposed action the PEP builds a PolicyInput (action, arguments, ChangeSet, request metadata,
session state, simulated clock), asks the arm's guard for a decision, logs the decision to the hash
chained audit log, and then either runs the tool or returns feedback to the agent. Any guard error is
turned into a deny (fail closed).
"""

from __future__ import annotations

import time
from typing import Any, Protocol

from changegate.contracts import ActionProposal, PolicyDecision, PolicyInput, Reason, ToolCallRecord
from changegate.feedback import FeedbackComposer
from changegate.plan_diff import sha256_json
from changegate.policy_input import build_policy_input, clip_args
from changegate.runtime import RunContext
from changegate.tools import ToolExecutor

# Actions whose PolicyInput carries the pending ChangeSet.
EVALUATED_ACTIONS = {"terraform_plan", "terraform_apply", "request_approval"}
FAIL_CLOSED_RULE = "PEP-FAIL-CLOSED"


class Guard(Protocol):
    name: str

    def decide(self, policy_input: PolicyInput, ctx: RunContext) -> PolicyDecision: ...


class NoGuard:
    """B0: every action is allowed (decisions are still logged)."""

    name = "none"

    def decide(self, policy_input: PolicyInput, ctx: RunContext) -> PolicyDecision:
        return PolicyDecision(decision="allow", guard=self.name, latency_ms=0.0)


class OpaGuard:
    """P: decisions come from the Rego bundle through OPA."""

    name = "opa"

    def __init__(self, client):
        self.client = client

    def decide(self, policy_input: PolicyInput, ctx: RunContext) -> PolicyDecision:
        return self.client.evaluate(policy_input)


def fail_closed(error: str, latency_ms: float = 0.0) -> PolicyDecision:
    return PolicyDecision(
        decision="deny",
        guard="fail_closed",
        latency_ms=latency_ms,
        error=error,
        reasons=[
            Reason(
                rule_id=FAIL_CLOSED_RULE,
                policy="pep",
                effect="deny",
                severity="critical",
                message="The policy engine could not evaluate this action, so it is blocked (fail closed).",
                hint="Retry the action. If it keeps failing, stop and explain the problem in submit.",
            )
        ],
    )


def _audit_view(policy_input: PolicyInput) -> dict[str, Any]:
    """The policy input as logged: everything except the bulky inventory (its digest is kept)."""
    data = policy_input.model_dump(mode="json")
    inventory = data.pop("inventory", {})
    data["inventory_digest"] = sha256_json(inventory)
    return data


class PEP:
    def __init__(self, ctx: RunContext, guard: Guard, feedback: FeedbackComposer, executor: ToolExecutor | None = None):
        self.ctx = ctx
        self.guard = guard
        self.feedback = feedback
        self.executor = executor or ToolExecutor(ctx)

    def decide(self, tool: str, args: dict[str, Any]):
        """Build the policy input and get a decision without running the tool."""
        ctx = self.ctx
        evaluation = ctx.workspace.evaluate() if tool in EVALUATED_ACTIONS else None
        if evaluation is not None:
            ctx.changeset_sources[evaluation.changeset.source] += 1
        session = ctx.store.snapshot(ctx.session_id, ctx.request.timestamp)
        policy_input = build_policy_input(
            action=tool,
            args=args,
            request=ctx.request,
            session=session,
            agent_id=ctx.agent_id,
            workspace=ctx.workspace,
            changeset=evaluation.changeset if evaluation else None,
        )
        started = time.perf_counter()
        try:
            decision = self.guard.decide(policy_input, ctx)
        except Exception as exc:  # any guard failure blocks the action
            decision = fail_closed(f"{type(exc).__name__}: {exc}", (time.perf_counter() - started) * 1000)
        return policy_input, decision, evaluation

    def handle(self, tool: str, args: dict[str, Any] | None = None) -> str:
        ctx = self.ctx
        args = dict(args or {})
        ctx.step += 1
        proposal = ActionProposal(
            request_id=ctx.request.id, step=ctx.step, tool=tool, args=clip_args(args), proposed_by=ctx.agent_id
        )
        policy_input, decision, evaluation = self.decide(tool, args)
        ctx.decision_latencies.append(decision.latency_ms)
        ctx.audit.append(
            "decision",
            request_id=ctx.request.id,
            session_id=ctx.session_id,
            sim_time=ctx.request.timestamp,
            action=tool,
            input_digest=sha256_json(policy_input.model_dump(mode="json")),
            payload={
                "step": ctx.step,
                "proposal": proposal.model_dump(mode="json"),
                "decision": decision.model_dump(mode="json"),
                "policy_input": _audit_view(policy_input),
            },
        )
        if decision.decision == "allow":
            observation, ok = self.executor.execute(tool, args, evaluation)
            executed = True
        else:
            observation, ok, executed = self.feedback.compose(decision), False, False
        ctx.records.append(
            ToolCallRecord(
                step=ctx.step,
                tool=tool,
                args=clip_args(args, limit=400),
                decision=decision.decision,
                rule_ids=decision.rule_ids,
                guard=decision.guard,
                latency_ms=round(decision.latency_ms, 2),
                executed=executed,
                ok=ok,
                observation=observation[:600],
            )
        )
        return observation
