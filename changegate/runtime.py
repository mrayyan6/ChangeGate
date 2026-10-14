"""Per request run context shared by the PEP, the tools and the agent loop."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from changegate.config import Config
from changegate.contracts import ChangeRequest, Scenario, ToolCallRecord
from changegate.workspace import Workspace


@dataclass
class RunContext:
    cfg: Config
    run_id: str
    arm: str
    scenario: Scenario
    request: ChangeRequest
    workspace: Workspace
    store: Any  # changegate.session_store.SessionStore
    approvals: Any  # changegate.approvals.ApprovalSimulator
    audit: Any  # changegate.audit.AuditLog
    agent_id: str
    step: int = 0
    records: list[ToolCallRecord] = field(default_factory=list)
    submitted: bool = False
    summary: str = ""
    stopped_by_guard: bool = False
    applies: int = 0
    approvals_requested: int = 0
    approvals_granted: int = 0
    changeset_sources: Counter = field(default_factory=Counter)
    decision_latencies: list[float] = field(default_factory=list)
    transcript: list[dict[str, Any]] = field(default_factory=list)

    @property
    def session_id(self) -> str:
        return self.request.session_id
