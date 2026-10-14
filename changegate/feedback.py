"""Feedback composer: the text the agent sees after the gate blocks an action.

The feedback mode is the G3 experimental variable, so the three main modes differ only in information
content:

    bare     "Action denied." and nothing else, for deny and require_approval alike
    reason   a header line, then one "- [<rule_id>] <message>" line per distinct reason
    hint     the reason text, then "How to fix:" and one "- <hint>" line per distinct hint

The reason text is always a prefix of the hint text. ``none`` (the no guard baseline, which never denies)
renders as bare and ``native`` (AgentSpec, which composes its own messages) renders as reason. Allowed
actions get no feedback. ``PolicyDecision.error`` is never shown: raw engine errors belong in the audit log.
"""

from __future__ import annotations

from changegate.contracts import PolicyDecision

MODES = ("none", "bare", "reason", "hint", "native")
# Modes without a format of their own, mapped to the format they borrow.
FALLBACK = {"none": "bare", "native": "reason"}

BARE_TEXT = "Action denied."
DENY_HEADER = "Action denied by policy."
APPROVAL_HEADER = "Action blocked: approval required."
HINT_HEADER = "How to fix:"
MAX_REASONS = 6
MAX_HINTS = 6


def _one_line(text: str | None) -> str:
    """Collapse whitespace, so a message can neither break the one line per reason layout nor forge lines."""
    return " ".join((text or "").split())


class FeedbackComposer:
    """Renders a blocking ``PolicyDecision`` as the observation handed back to the agent."""

    def __init__(self, mode: str) -> None:
        if mode not in MODES:
            raise ValueError(f"unknown feedback mode {mode!r}, expected one of: {', '.join(MODES)}")
        self.mode = mode
        self.effective_mode = FALLBACK.get(mode, mode)

    def compose(self, decision: PolicyDecision) -> str:
        """Feedback for ``decision``, or an empty string when it allows the action."""
        if decision.decision == "allow":
            return ""
        if self.effective_mode == "bare":
            return BARE_TEXT
        lines = [APPROVAL_HEADER if decision.decision == "require_approval" else DENY_HEADER]
        # distinct (rule_id, message) pairs in the order given; the first occurrence wins
        pairs = list(dict.fromkeys((_one_line(r.rule_id), _one_line(r.message)) for r in decision.reasons))
        lines += [f"- [{rule_id}] {message}".rstrip() for rule_id, message in pairs[:MAX_REASONS]]
        if len(pairs) > MAX_REASONS:
            lines.append(f"- ({len(pairs) - MAX_REASONS} more not shown)")
        if self.effective_mode == "hint":
            # hints come from every reason, also those past the cap; no header when there is nothing to add
            hints = [h for h in dict.fromkeys(_one_line(r.hint) for r in decision.reasons) if h]
            if hints:
                lines.append(HINT_HEADER)
                lines += [f"- {hint}" for hint in hints[:MAX_HINTS]]
        return "\n".join(lines)
