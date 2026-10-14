"""B1 baseline: AgentSpec's own ControlledAgentExecutor enforcing the ChangeGate controls.

AgentSpec (Wang, Poskitt and Sun, ICSE 2026) is used natively from external/AgentSpec (set up by
scripts/setup_agentspec.py, never copied into this repo). Our code only provides:
* the rules, written in AgentSpec's DSL (baselines/agentspec_rules/changegate.spec);
* the predicates those rules call (baselines/agentspec_predicates.py);
* two small adapters. AgentSpec's executor checks one action at a time and its trigger test calls .strip()
  on the tool input, because it was built for single-string ReAct tools. SingleActionAdapter hands it the
  tool-calling agent's actions one at a time, as a dict that also answers .strip().
* an answer source for AgentSpec's user_inspection enforcement: instead of a person at the keyboard, the
  same deterministic approval simulator the other arms use decides.

The PEP still wraps every tool in pass-through mode (guard none), so actions that AgentSpec lets through are
logged like in every other arm, and AgentSpec's own interventions are logged by the predicates.
"""

from __future__ import annotations

import builtins
import contextlib
import io
import re
import sys
from pathlib import Path
from typing import Any

from langchain.agents import create_tool_calling_agent
from langchain.agents.agent import BaseSingleActionAgent, RunnableMultiActionAgent
from langchain.agents.output_parsers.tools import ToolAgentAction
from langchain_core.agents import AgentFinish
from langchain_core.messages import AIMessage

from baselines.agentspec_predicates import CONTROLS, CURRENT, make_predicate
from changegate.agent import AgentOutcome, build_prompt, run_agent_loop
from changegate.config import REPO_ROOT
from changegate.runtime import RunContext
from changegate.tools import build_tools

AGENTSPEC_SRC = REPO_ROOT / "external" / "AgentSpec" / "src"
RULES_FILE = Path(__file__).resolve().parent / "agentspec_rules" / "changegate.spec"
STOP_MARKER = "action stopped by"


def ensure_importable() -> None:
    if not (AGENTSPEC_SRC / "spec_lang" / "AgentSpecParser.py").exists():
        raise RuntimeError("AgentSpec is not set up: run scripts/setup_agentspec.py")
    if str(AGENTSPEC_SRC) not in sys.path:
        sys.path.insert(0, str(AGENTSPEC_SRC))


def load_rules() -> list:
    """Parse every rule in the .spec file with AgentSpec's own parser (one rule per Rule object)."""
    ensure_importable()
    from rule import Rule

    text = "\n".join(line for line in RULES_FILE.read_text(encoding="utf-8").splitlines() if not line.startswith("#"))
    chunks = [c.strip() for c in re.split(r"(?m)^end\s*$", text) if c.strip()]
    return [Rule.from_text(chunk + "\nend\n") for chunk in chunks]


class ToolInput(dict):
    """A tool input dict that also answers .strip(), which AgentSpec's Rule.triggered calls."""

    def strip(self) -> str:
        return ""


class SpecAction(ToolAgentAction):
    """A LangChain tool action that also offers AgentSpec's Action interface.

    AgentSpec's llm_self_reflect hands the raw result of agent.plan back to validate_and_enforce, which
    expects AgentSpec's own Action wrapper (is_finish, is_skip, name, input, unwrap). Giving the LangChain
    action that small interface lets AgentSpec's native enforcement run without changing its code.
    """

    @property
    def name(self) -> str:
        return self.tool

    @property
    def input(self) -> Any:
        return self.tool_input

    def is_finish(self) -> bool:
        return False

    def is_skip(self) -> bool:
        return False

    def unwrap(self) -> "SpecAction":
        return self


class SpecFinish(AgentFinish):
    """AgentFinish with the same AgentSpec Action interface (see SpecAction)."""

    @property
    def name(self) -> str:
        return "finish"

    @property
    def input(self) -> Any:
        return None

    def is_finish(self) -> bool:
        return True

    def is_skip(self) -> bool:
        return False

    def unwrap(self) -> "SpecFinish":
        return self


class SingleActionAdapter(BaseSingleActionAgent):
    """Wraps the tool-calling agent so AgentSpec's executor sees one action per step."""

    inner: Any
    default_callbacks: list = []

    @property
    def input_keys(self) -> list[str]:
        return []

    def plan(self, intermediate_steps, callbacks=None, **kwargs):
        out = self.inner.plan(intermediate_steps, callbacks=callbacks or self.default_callbacks, **kwargs)
        if isinstance(out, AgentFinish):
            return SpecFinish(return_values=out.return_values, log=out.log)
        actions = out if isinstance(out, list) else [out]
        first = actions[0]
        log = list(getattr(first, "message_log", []) or [])
        call_id = getattr(first, "tool_call_id", "") or ""
        if log and isinstance(log[-1], AIMessage) and len(log[-1].tool_calls) > 1:
            ai = log[-1]
            keep = [tc for tc in ai.tool_calls if tc.get("id") == call_id] or ai.tool_calls[:1]
            log[-1] = AIMessage(content=ai.content, tool_calls=keep, id=ai.id)
        action = SpecAction(tool=first.tool, tool_input=first.tool_input, log=first.log, message_log=log, tool_call_id=call_id)
        tool_input = first.tool_input if isinstance(first.tool_input, dict) else {"input": first.tool_input}
        object.__setattr__(action, "tool_input", ToolInput(tool_input))
        return action

    async def aplan(self, intermediate_steps, callbacks=None, **kwargs):  # pragma: no cover
        raise NotImplementedError("the B1 arm runs synchronously")


def _inspection_answer(prompt: str = "") -> str:
    """Stands in for the person AgentSpec's user_inspection asks: the approval simulator decides."""
    ctx: RunContext = CURRENT["ctx"]
    evaluation = ctx.workspace.evaluate()
    approval = ctx.approvals.decide(
        request=ctx.request,
        decision=ctx.scenario.approval_decision,
        reason="AgentSpec user_inspection of a pending terraform_apply",
        changeset_digest=evaluation.changeset.digest,
        step=ctx.step,
    )
    ctx.store.add_approval(ctx.session_id, approval)
    ctx.approvals_requested += 1
    ctx.approvals_granted += int(approval.granted)
    ctx.audit.append(
        "approval",
        request_id=ctx.request.id,
        session_id=ctx.session_id,
        sim_time=ctx.request.timestamp,
        action="user_inspection",
        payload={"approval": approval.model_dump(mode="json")},
    )
    return "yes" if approval.granted else "no"


def run_agentspec_agent(ctx: RunContext, llm, pep, max_steps: int, callbacks: list | None = None) -> AgentOutcome:
    ensure_importable()
    from controlled_agent_excector import ControlledAgentExecutor
    from rules.manual import table

    for control in CONTROLS:
        table.predicate_table[control.predicate] = make_predicate(control)
    rules = load_rules()
    tools = build_tools(pep)
    inner = RunnableMultiActionAgent(runnable=create_tool_calling_agent(llm, tools, build_prompt()), stream_runnable=False)
    adapter = SingleActionAdapter(inner=inner, default_callbacks=list(callbacks or []))

    def make_executor(remaining: int):
        return ControlledAgentExecutor.from_agent_and_tools(
            agent=adapter, tools=tools, rules=rules, max_iterations=remaining, early_stopping_method="force"
        )

    CURRENT["ctx"] = ctx
    real_input = builtins.input
    builtins.input = _inspection_answer
    try:
        with contextlib.redirect_stdout(io.StringIO()):  # AgentSpec prints every predicate it evaluates
            outcome = run_agent_loop(ctx, make_executor, max_steps, callbacks, stop_marker=STOP_MARKER)
    finally:
        builtins.input = real_input
        CURRENT["ctx"] = None
    if ctx.stopped_by_guard and not ctx.submitted:
        return AgentOutcome("stopped_by_guard", outcome.steps, outcome.final_output)
    return outcome
