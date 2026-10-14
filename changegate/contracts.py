"""Pydantic v2 contracts shared by every ChangeGate module.

Modules exchange data only through these models. ``scripts/export_schemas.py`` writes each top level
contract to ``schemas/<Name>.schema.json``.

Rule: nothing from the scenario answer key (label, category, violated controls, assertions) may appear
in ``PolicyInput``. The gate has to decide from the request, the change and the session alone.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ResourceAction = Literal["create", "update", "delete"]
DecisionKind = Literal["allow", "deny", "require_approval"]
ToolName = Literal[
    "list_files",
    "read_file",
    "edit_file",
    "terraform_plan",
    "request_approval",
    "terraform_apply",
    "submit",
]
Category = Literal["security", "blast_radius", "change_window", "sod_approval", "split_change", "injection"]
Label = Literal["safe", "unsafe"]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")


# Change requests


class Ticket(Contract):
    id: str
    title: str = ""
    body: str = ""


class ChangeRequest(Contract):
    """What the agent and the gate are allowed to know about a request."""

    id: str
    session_id: str
    requester: str
    approver: str | None = None
    ticket: Ticket
    timestamp: datetime = Field(description="Simulated clock for this request (UTC).")
    text: str = Field(description="The change request text handed to the agent.")


class ActionProposal(Contract):
    """A tool call the agent wants to make, captured before the PEP decides."""

    request_id: str
    step: int
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    proposed_by: str = "changegate-agent"


# Change sets


class ResourceChange(Contract):
    address: str
    type: str
    name: str
    action: ResourceAction
    changed_attributes: list[str] = Field(default_factory=list)
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    unknown_after: list[str] = Field(
        default_factory=list, description="Top level attributes that are only known after apply."
    )
    references: dict[str, list[str]] = Field(
        default_factory=dict, description="Attribute name to the resource addresses it references."
    )


class ChangeSummary(Contract):
    create: int = 0
    update: int = 0
    delete: int = 0

    @property
    def total(self) -> int:
        return self.create + self.update + self.delete


class ChangeSet(Contract):
    """Normalized difference between the deployed state and the proposed configuration."""

    source: Literal["plan", "hcl_fallback"]
    fallback_reason: str | None = None
    changes: list[ResourceChange] = Field(default_factory=list)
    summary: ChangeSummary = Field(default_factory=ChangeSummary)
    base_digest: str = Field(description="SHA-256 of the deployed state the diff starts from.")
    target_digest: str = Field(description="SHA-256 of the proposed state.")
    digest: str = Field(description="SHA-256 of the normalized changes; approvals bind to this.")
    plan_ms: float = 0.0
    plan_cached: bool = False
    errors: list[str] = Field(default_factory=list)


# Session state handed to the policies


class Approval(Contract):
    approval_id: str
    request_id: str
    ticket_id: str
    requester: str
    approver: str | None = None
    granted: bool
    reason: str = ""
    detail: str = ""
    changeset_digest: str
    timestamp: datetime


class WindowTotals(Contract):
    window_id: str
    creates: int = 0
    updates: int = 0
    deletes: int = 0
    changes: int = 0
    applies: int = 0


class SessionState(Contract):
    session_id: str
    window_id: str
    window_totals: WindowTotals
    approvals: list[Approval] = Field(default_factory=list)
    requests_seen: int = 0


class Clock(Contract):
    now: datetime = Field(description="Simulated time, fixed for the whole request.")


class AgentIdentity(Contract):
    id: str = "changegate-agent"


class PathInfo(Contract):
    """Normalized target path for file actions, computed by the PEP from the raw argument."""

    raw: str
    normalized: str
    escapes_workspace: bool = False


class InventoryItem(Contract):
    """Compact view of one deployed (or newly created) resource, for rules that need context."""

    type: str
    name: str | None = Field(default=None, description="bucket, identifier or name attribute when known")
    tags: dict[str, Any] = Field(default_factory=dict)


class PolicyInput(Contract):
    action: str
    args: dict[str, Any] = Field(default_factory=dict)
    path: PathInfo | None = None
    changeset: ChangeSet | None = None
    inventory: dict[str, InventoryItem] = Field(
        default_factory=dict, description="Deployed resources plus resources created by the changeset."
    )
    request: ChangeRequest
    session: SessionState
    clock: Clock
    agent: AgentIdentity = Field(default_factory=AgentIdentity)


# Decisions


class Reason(Contract):
    rule_id: str
    policy: str
    effect: Literal["deny", "require_approval"]
    message: str
    hint: str = ""
    severity: Literal["low", "medium", "high", "critical"] = "high"
    resource: str | None = None


class PolicyDecision(Contract):
    decision: DecisionKind
    reasons: list[Reason] = Field(default_factory=list)
    guard: str = Field(description="none, opa, trivy, agentspec or fail_closed")
    latency_ms: float = 0.0
    bundle_digest: str | None = None
    error: str | None = None

    @property
    def rule_ids(self) -> list[str]:
        return [r.rule_id for r in self.reasons]


# Audit log


class AuditRecord(Contract):
    seq: int
    timestamp: datetime
    sim_time: datetime | None = None
    run_id: str
    arm: str
    request_id: str | None = None
    session_id: str | None = None
    event: Literal["run_start", "decision", "approval", "apply", "run_end"]
    action: str | None = None
    input_digest: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str
    hash: str


# Scenarios and evaluation


AssertionType = Literal[
    "resource_exists",
    "resource_absent",
    "attr_equals",
    "attr_contains",
    "attr_not_contains",
    "no_delete_of",
    "max_absent",
    "sg_ingress",
    "resource_matches",
]


class Assertion(Contract):
    """End state check on the final deployed state. Evaluated in Python, never through Rego.

    resource_matches: ``address`` is a glob (for example ``aws_iam_role.*``); it passes when the existence of
    a matching resource whose ``path`` contains ``value`` equals ``present``. It does not depend on the
    names an agent picks for new resources.
    """

    type: AssertionType
    address: str | None = None
    addresses: list[str] | None = None
    path: str | None = None
    value: Any = None
    max: int | None = None
    sg: str | None = Field(default=None, description="sg_ingress: security group address, or '*' for any")
    port: int | None = None
    cidr: str | None = None
    present: bool | None = None
    note: str = ""


class AssertionResult(Contract):
    assertion: Assertion
    passed: bool
    detail: str = ""


class FileEdit(Contract):
    """Exact string edit. ``old`` empty means create the file with ``new`` as its content."""

    path: str
    old: str = ""
    new: str


class OracleScript(Contract):
    """Scripted literal fulfilment used to validate scenarios and policies without an LLM."""

    edits: list[FileEdit] = Field(default_factory=list)
    request_approval: bool = True
    approval_reason: str = "Requesting approval for the change described in the ticket."


class Scenario(Contract):
    id: str
    twin_id: str
    session_id: str
    sequence: int = Field(default=0, description="Order of the request inside its session.")
    category: Category
    label: Label
    requester: str
    approver: str | None = None
    approval_decision: Literal["approve", "reject"] = "approve"
    ticket: Ticket
    timestamp: datetime
    request: str
    violated_controls: list[str] = Field(default_factory=list)
    assertions: list[Assertion]
    compliant_assertions: list[Assertion] | None = None
    workspace_patches: list[FileEdit] = Field(default_factory=list)
    oracle: OracleScript = Field(default_factory=OracleScript)
    notes: str = ""

    def to_change_request(self) -> ChangeRequest:
        return ChangeRequest(
            id=self.id,
            session_id=self.session_id,
            requester=self.requester,
            approver=self.approver,
            ticket=self.ticket,
            timestamp=self.timestamp,
            text=self.request,
        )


# Run results


class ToolCallRecord(Contract):
    step: int
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    decision: DecisionKind
    rule_ids: list[str] = Field(default_factory=list)
    guard: str = "none"
    latency_ms: float = 0.0
    executed: bool = False
    ok: bool = True
    observation: str = ""


class TokenUsage(Contract):
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    llm_calls: int = 0
    cache_hits: int = 0


class LatencyStats(Contract):
    n: int = 0
    mean_ms: float = 0.0
    p50_ms: float = 0.0
    max_ms: float = 0.0


class RunResult(Contract):
    run_id: str
    arm: str
    agent: Literal["llm", "oracle"]
    provider: str
    model: str
    seed: int | None = None
    guard: str
    feedback_mode: str
    scenario_id: str
    twin_id: str
    session_id: str
    category: Category
    label: Label
    status: Literal["submitted", "finished_without_submit", "max_steps", "stopped_by_guard", "error"]
    summary: str = ""
    steps: int = 0
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    decision_counts: dict[str, int] = Field(default_factory=dict)
    denied_rule_ids: list[str] = Field(default_factory=list)
    approvals_requested: int = 0
    approvals_granted: int = 0
    applies: int = 0
    tokens: TokenUsage = Field(default_factory=TokenUsage)
    cost_usd: float = 0.0
    decision_latency: LatencyStats = Field(default_factory=LatencyStats)
    wall_time_s: float = 0.0
    changeset_sources: dict[str, int] = Field(default_factory=dict)
    assertions: list[AssertionResult] = Field(default_factory=list)
    assertions_passed: bool = False
    compliant_assertions: list[AssertionResult] | None = None
    compliant_passed: bool | None = None
    final_state_digest: str = ""
    error: str | None = None


SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "ChangeRequest": ChangeRequest,
    "ActionProposal": ActionProposal,
    "ChangeSet": ChangeSet,
    "PolicyInput": PolicyInput,
    "PolicyDecision": PolicyDecision,
    "AuditRecord": AuditRecord,
    "RunResult": RunResult,
    "Scenario": Scenario,
}
