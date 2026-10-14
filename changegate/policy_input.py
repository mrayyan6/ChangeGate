"""Build the PolicyInput the gate sends to OPA (and that the baselines receive too)."""

from __future__ import annotations

from typing import Any

from changegate.contracts import (
    AgentIdentity,
    ChangeRequest,
    ChangeSet,
    Clock,
    InventoryItem,
    PolicyInput,
    SessionState,
)
from changegate.plan_diff import State

FILE_ACTIONS = {"read_file", "edit_file"}
MAX_ARG_CHARS = 4000


def _name_of(values: dict[str, Any]) -> str | None:
    for key in ("bucket", "identifier", "name"):
        value = values.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def inventory_from_state(state: State, changeset: ChangeSet | None = None) -> dict[str, InventoryItem]:
    inventory: dict[str, InventoryItem] = {}
    for address, res in state.items():
        values = res.get("values") or {}
        tags = values.get("tags") if isinstance(values.get("tags"), dict) else {}
        inventory[address] = InventoryItem(type=res["type"], name=_name_of(values), tags=tags or {})
    for change in (changeset.changes if changeset else []):
        if change.action == "create" and change.after is not None:
            tags = change.after.get("tags") if isinstance(change.after.get("tags"), dict) else {}
            inventory[change.address] = InventoryItem(type=change.type, name=_name_of(change.after), tags=tags or {})
    return inventory


def clip_args(args: dict[str, Any], limit: int = MAX_ARG_CHARS) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in (args or {}).items():
        if isinstance(value, str) and len(value) > limit:
            value = value[:limit] + f"... [{len(value)} characters]"
        out[key] = value
    return out


def build_policy_input(
    *,
    action: str,
    args: dict[str, Any],
    request: ChangeRequest,
    session: SessionState,
    agent_id: str,
    workspace=None,
    changeset: ChangeSet | None = None,
) -> PolicyInput:
    path = None
    if action in FILE_ACTIONS and workspace is not None:
        path = workspace.resolve_path(str((args or {}).get("path", "")))
    inventory = inventory_from_state(workspace.deployed, changeset) if workspace is not None else {}
    return PolicyInput(
        action=action,
        args=clip_args(args),
        path=path,
        changeset=changeset,
        inventory=inventory,
        request=request,
        session=session,
        clock=Clock(now=request.timestamp),
        agent=AgentIdentity(id=agent_id),
    )
