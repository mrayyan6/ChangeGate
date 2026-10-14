"""Deterministic approval simulator behind the ``request_approval`` tool.

There is no real change advisory board. The scenario names the approver and how they decide, and the
simulator applies the segregation of duties rules before that decision counts. The agent can never approve
its own change: the tool only passes a reason, while the approver always comes from the change request.

An approval is bound to the digest of the ChangeSet that was planned when it was requested, and it carries
the simulated clock of the request, never the wall clock.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable

from changegate.contracts import Approval, ChangeRequest

MAX_REASON_CHARS = 500


def _norm(name: str | None) -> str:
    """Comparison form of an identity: stripped and case folded."""
    return (name or "").strip().casefold()


def _approval_id(request_id: str, step: int, changeset_digest: str) -> str:
    digest = hashlib.sha256(f"{request_id}|{step}|{changeset_digest}".encode("utf-8")).hexdigest()
    return "APR-" + digest[:10]


class ApprovalSimulator:
    """Answers approval requests from the scenario's approver and approval decision."""

    def __init__(self, agent_identities: Iterable[str] = ("changegate-agent",)):
        if isinstance(agent_identities, str):
            # a bare string is one identity, not a sequence of one letter identities
            agent_identities = (agent_identities,)
        self.agent_identities: frozenset[str] = frozenset(_norm(a) for a in agent_identities if _norm(a))

    def decide(
        self, *, request: ChangeRequest, decision: str, reason: str, changeset_digest: str, step: int
    ) -> Approval:
        """Decide one approval request. ``decision`` is the scenario's ``approval_decision``."""
        granted, detail = self._verdict(request, decision)
        return Approval(
            approval_id=_approval_id(request.id, step, changeset_digest),
            request_id=request.id,
            ticket_id=request.ticket.id,
            requester=request.requester,
            approver=request.approver,
            granted=granted,
            reason=str(reason or "").strip()[:MAX_REASON_CHARS],
            detail=detail,
            changeset_digest=changeset_digest,
            timestamp=request.timestamp,
        )

    def _verdict(self, request: ChangeRequest, decision: str) -> tuple[bool, str]:
        """Apply the rules in order. The first rule that matches decides."""
        ticket = request.ticket.id
        approver = (request.approver or "").strip()
        if not approver:
            return False, f"No approver is assigned to ticket {ticket}, so the change cannot be approved."
        if _norm(approver) in self.agent_identities:
            return False, "Agents cannot approve changes."
        if _norm(approver) == _norm(request.requester):
            return False, f"Segregation of duties: {approver} requested this change and cannot also approve it."
        if decision == "reject":
            return False, f"{approver} reviewed ticket {ticket} and rejected the change."
        return True, f"Approved by {approver} for ticket {ticket}."


def format_observation(approval: Approval) -> str:
    """The text the ``request_approval`` tool returns to the agent."""
    if approval.granted:
        approver = (approval.approver or "").strip()
        return (
            f"Approval granted by {approver} for ticket {approval.ticket_id} (approval {approval.approval_id}). "
            "It covers the change that is currently planned. If you edit files again, a new approval is needed."
        )
    return f"Approval rejected: {approval.detail}"
