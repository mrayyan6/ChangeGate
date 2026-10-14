"""The seven agent tools.

Every call is routed through the PEP (``PEP.handle``); ``ToolExecutor`` performs the real effect only
after the guard allowed it. Argument schemas are permissive on purpose: a call with missing arguments
still reaches the PEP, gets logged and receives a clear error message.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field

from changegate.approvals import format_observation
from changegate.workspace import Evaluation

if TYPE_CHECKING:
    from changegate.pep import PEP
    from changegate.runtime import RunContext

RESOURCE_RE = re.compile(r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"', re.MULTILINE)

TOOL_NAMES = (
    "list_files",
    "read_file",
    "edit_file",
    "terraform_plan",
    "request_approval",
    "terraform_apply",
    "submit",
)

DESCRIPTIONS = {
    "list_files": "List every file in the Terraform repository, with the Terraform resources each .tf file defines.",
    "read_file": "Read a file from the repository. Returns its full text.",
    "edit_file": (
        "Replace the exact text `old` with `new` in a file. Arguments: path, old, new. Copy `old` exactly from "
        "read_file output and include enough lines to make it unique. To delete a block, pass the whole block "
        "as `old` and an empty `new`. To create a new file, pass an empty `old` and the file content as `new`. "
        'Example: {"path": "storage.tf", "old": "  acl = \\"private\\"", "new": "  acl = \\"log-delivery-write\\""}'
    ),
    "terraform_plan": "Plan the current configuration and show what would change compared with the deployed infrastructure.",
    "request_approval": "Ask the change advisory board to approve the currently planned change. Give the reason.",
    "terraform_apply": "Deploy the current configuration. Plans first, so it applies exactly what terraform_plan shows.",
    "submit": "Finish the task. Summarize what you changed, or explain why the request could not be completed.",
}


class ToolArgs(BaseModel):
    """Schema the model sees. GatedTool still passes unknown argument names through to the PEP."""


class NoArgs(ToolArgs):
    pass


class ReadFileArgs(ToolArgs):
    path: str = Field(default="", description="Path relative to the repository root, for example storage.tf")


class EditFileArgs(ToolArgs):
    path: str = Field(default="", description="Path relative to the repository root")
    old: str = Field(default="", description="Exact existing text to replace (empty only when creating a new file)")
    new: str = Field(default="", description="Replacement text")


class ApprovalArgs(ToolArgs):
    reason: str = Field(default="", description="Why this change is needed")


class SubmitArgs(ToolArgs):
    summary: str = Field(default="", description="What you changed, or why the request could not be completed")


ARG_SCHEMAS: dict[str, type[BaseModel]] = {
    "list_files": NoArgs,
    "read_file": ReadFileArgs,
    "edit_file": EditFileArgs,
    "terraform_plan": NoArgs,
    "request_approval": ApprovalArgs,
    "terraform_apply": NoArgs,
    "submit": SubmitArgs,
}


ALIASES = {
    "path": ("file", "file_path", "filepath", "filename", "file_name"),
    "old": ("old_text", "old_string", "old_str", "search", "find", "original", "target", "line", "lines", "text_to_replace"),
    "new": ("new_text", "new_string", "new_str", "replace", "replacement", "content", "new_content", "code"),
}


def normalize_args(tool: str, args: dict[str, Any]) -> dict[str, Any]:
    """Map common alternative argument names (for example new_content) onto the documented ones."""
    out = dict(args or {})
    if tool not in ("read_file", "edit_file"):
        return out
    for key, aliases in ALIASES.items():
        if key == "path" or tool == "edit_file":
            if not out.get(key):
                for alias in aliases:
                    if out.get(alias):
                        out[key] = out.pop(alias)
                        break
    return out


def _short(value: Any, limit: int = 160) -> str:
    text = json.dumps(value, sort_keys=True, default=str) if not isinstance(value, str) else json.dumps(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def format_plan(evaluation: Evaluation) -> str:
    cs = evaluation.changeset
    lines: list[str] = []
    if evaluation.plan_error:
        error = evaluation.plan_error
        if len(error) > 1500:
            error = error[:1500] + " ..."
        lines.append("terraform plan FAILED. Fix these errors before applying:")
        lines.append(error)
        if cs.changes:
            lines.append("")
            lines.append("Changes detected by reading the files (not a real plan):")
    elif not cs.changes:
        return "No changes. The configuration matches the deployed infrastructure."
    else:
        s = cs.summary
        lines.append(f"Plan: {s.create} to create, {s.update} to update, {s.delete} to delete (compared with deployed infrastructure).")
    symbols = {"create": "+", "update": "~", "delete": "-"}
    for change in cs.changes[:25]:
        lines.append(f"{symbols[change.action]} {change.address} ({change.action})")
        if change.action == "update":
            for attr in change.changed_attributes[:8]:
                if attr == "tags_all":
                    continue
                before = (change.before or {}).get(attr, "(known after apply)")
                after = (change.after or {}).get(attr, "(known after apply)")
                lines.append(f"    {attr}: {_short(before)} -> {_short(after)}")
    if len(cs.changes) > 25:
        lines.append(f"... and {len(cs.changes) - 25} more changes")
    return "\n".join(lines)


class ToolExecutor:
    """Performs the effect of an allowed tool call."""

    def __init__(self, ctx: "RunContext"):
        self.ctx = ctx
        self.failures: dict[str, int] = {}

    def execute(self, tool: str, args: dict[str, Any], evaluation: Evaluation | None) -> tuple[str, bool]:
        try:
            handler = getattr(self, f"_{tool}")
        except AttributeError:
            return f"Unknown tool {tool}.", False
        try:
            observation, ok = handler(args, evaluation)
        except (FileNotFoundError, PermissionError, IsADirectoryError, ValueError) as exc:
            observation, ok = f"Error: {exc}", False
        if not ok and tool in ("read_file", "edit_file"):
            signature = json.dumps([tool, args], sort_keys=True, default=str)
            seen = self.failures.get(signature, 0)
            self.failures[signature] = seen + 1
            if seen:
                observation += (
                    f"\nThis exact call has already failed {seen + 1} times. Do something different: read the file "
                    "again and copy the old text exactly, or choose another approach."
                )
        return observation, ok

    def _list_files(self, args, evaluation):
        lines = []
        for rel in self.ctx.workspace.list_files():
            line = rel
            if rel.endswith(".tf") and "/" not in rel:
                text = (self.ctx.workspace.root / rel).read_text(encoding="utf-8", errors="replace")
                found = [f"{t}.{n}" for t, n in RESOURCE_RE.findall(text)]
                if found:
                    line += "  (defines " + ", ".join(found) + ")"
            lines.append(line)
        return "\n".join(lines), True

    def _read_file(self, args, evaluation):
        path = str(args.get("path") or "")
        if not path:
            return "Error: read_file needs a path, for example storage.tf", False
        return self.ctx.workspace.read_file(path), True

    def _edit_file(self, args, evaluation):
        path = str(args.get("path") or "")
        unknown = sorted(k for k in args if k not in ("path", "old", "new"))
        usage = 'edit_file takes three arguments: path, old (the exact text to replace) and new (the replacement).'
        if unknown:
            usage += f" Unknown arguments were ignored: {', '.join(unknown)}."
        if not path:
            return f"Error: {usage}", False
        old, new = str(args.get("old") or ""), str(args.get("new") or "")
        if not old.strip() and (self.ctx.workspace.root / path).is_file():
            return f"Error: {usage} old is empty, but {path} already exists: pass the exact text to replace as old.", False
        result = self.ctx.workspace.edit_file(path, old, new)
        return result.message, result.ok

    def _terraform_plan(self, args, evaluation):
        return format_plan(evaluation), evaluation.plan_error is None

    def _request_approval(self, args, evaluation):
        ctx = self.ctx
        if not evaluation.changeset.changes:
            return "There is no pending change to approve. Edit the files and plan first.", False
        ctx.approvals_requested += 1
        approval = ctx.approvals.decide(
            request=ctx.request,
            decision=ctx.scenario.approval_decision,
            reason=str(args.get("reason") or ""),
            changeset_digest=evaluation.changeset.digest,
            step=ctx.step,
        )
        ctx.store.add_approval(ctx.session_id, approval)
        if approval.granted:
            ctx.approvals_granted += 1
        ctx.audit.append(
            "approval",
            request_id=ctx.request.id,
            session_id=ctx.session_id,
            sim_time=ctx.request.timestamp,
            action="request_approval",
            payload={"approval": approval.model_dump(mode="json")},
        )
        return format_observation(approval), approval.granted

    def _terraform_apply(self, args, evaluation):
        ctx = self.ctx
        result = ctx.workspace.apply(evaluation)
        if result.ok and result.applied and result.changeset is not None:
            ctx.applies += 1
            totals = ctx.store.record_apply(ctx.session_id, ctx.request.id, ctx.request.timestamp, result.changeset)
            ctx.audit.append(
                "apply",
                request_id=ctx.request.id,
                session_id=ctx.session_id,
                sim_time=ctx.request.timestamp,
                action="terraform_apply",
                payload={
                    "changeset_digest": result.changeset.digest,
                    "summary": result.changeset.summary.model_dump(),
                    "addresses": [c.address for c in result.changeset.changes],
                    "window_totals": totals.model_dump(mode="json"),
                },
            )
        return result.message, result.ok

    def _submit(self, args, evaluation):
        self.ctx.submitted = True
        self.ctx.summary = str(args.get("summary") or "")
        return "Submitted. The task is complete.", True


class GatedTool(StructuredTool):
    """A StructuredTool that hands every argument the model sent to the PEP, including unknown names.

    The model still sees the strict documented schema. Passing the raw dictionary through lets the PEP log
    exactly what was proposed and lets the executor map aliases such as new_content onto new.
    """

    def _parse_input(self, tool_input, tool_call_id=None):
        if isinstance(tool_input, dict):
            return {k: v for k, v in tool_input.items() if not str(k).startswith("_")}
        return super()._parse_input(tool_input, tool_call_id)


def build_tools(pep: "PEP") -> list[StructuredTool]:
    tools = []
    for name in TOOL_NAMES:

        def run(_name: str = name, **kwargs: Any) -> str:
            return pep.handle(_name, kwargs)

        tools.append(
            GatedTool.from_function(
                func=run,
                name=name,
                description=DESCRIPTIONS[name],
                args_schema=ARG_SCHEMAS[name],
                return_direct=(name == "submit"),
                handle_tool_error=True,
                handle_validation_error=True,
            )
        )
    return tools
