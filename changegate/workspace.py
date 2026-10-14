"""Agent sandbox: a copy of an env plus the session's deployed state.

Layout of one session directory::

    <dest>/repo/    files the agent can list, read and edit
    <dest>/state/   initial.json, deployed.json, deployed_files.json (never visible to the agent)

The deployed state starts as the planned values of the unmodified repo. A successful simulated apply
replaces it with the planned values of the edited files.
"""

from __future__ import annotations

import difflib
import json
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from changegate.contracts import ChangeSet, FileEdit, PathInfo
from changegate.plan_diff import State, build_changeset, changeset_from_hcl, state_from_plan
from changegate.terraform import TerraformRunner, files_digest, read_text, root_module_files

IGNORED = shutil.ignore_patterns(".terraform", "*.tfstate", "*.tfstate.*", "tfplan", "*.tfplan", "__pycache__")
MAX_READ_CHARS = 12000
MAX_EDIT_CHARS = 50000


@dataclass
class Evaluation:
    files_digest: str
    changeset: ChangeSet
    after_state: State | None
    plan_error: str | None = None


@dataclass
class ApplyResult:
    ok: bool
    applied: bool
    message: str
    changeset: ChangeSet | None = None


@dataclass
class EditResult:
    ok: bool
    message: str
    fuzzy: bool = False
    created: bool = False
    extra: dict = field(default_factory=dict)


def _write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=1, sort_keys=True, default=str), encoding="utf-8")


def _norm_line(line: str) -> str:
    return " ".join(line.split())


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


class Workspace:
    def __init__(self, dest: Path, runner: TerraformRunner):
        self.dest = Path(dest)
        self.root = self.dest / "repo"
        self.state_dir = self.dest / "state"
        self.runner = runner
        self.initial: State = json.loads((self.state_dir / "initial.json").read_text(encoding="utf-8"))
        self.deployed: State = json.loads((self.state_dir / "deployed.json").read_text(encoding="utf-8"))
        self.deployed_files: dict[str, str] = json.loads(
            (self.state_dir / "deployed_files.json").read_text(encoding="utf-8")
        )

    # creation

    @classmethod
    def create(
        cls, env_dir: Path, dest: Path, runner: TerraformRunner, patches: list[FileEdit] | None = None
    ) -> "Workspace":
        dest = Path(dest)
        root, state_dir = dest / "repo", dest / "state"
        if root.exists():
            raise FileExistsError(f"workspace already exists: {root}")
        shutil.copytree(env_dir, root, ignore=IGNORED)
        state_dir.mkdir(parents=True, exist_ok=True)
        for patch in patches or []:
            result = _apply_edit(root, patch.path, patch.old, patch.new, tolerant=False)
            if not result.ok:
                raise ValueError(f"workspace patch failed for {patch.path}: {result.message}")
        files = root_module_files(root)
        outcome = runner.plan(files)
        if not outcome.ok:
            raise RuntimeError(f"baseline plan failed for {env_dir}: {outcome.error}")
        state = state_from_plan(outcome.plan)
        _write_json(state_dir / "initial.json", state)
        _write_json(state_dir / "deployed.json", state)
        _write_json(state_dir / "deployed_files.json", files)
        return cls(dest, runner)

    @classmethod
    def open_or_create(
        cls, env_dir: Path, dest: Path, runner: TerraformRunner, patches: list[FileEdit] | None = None
    ) -> "Workspace":
        if (Path(dest) / "state" / "deployed.json").exists():
            return cls(dest, runner)
        return cls.create(env_dir, dest, runner, patches)

    # paths and files

    def resolve_path(self, raw: str) -> PathInfo:
        text = str(raw or "").strip().strip('"').strip("'")
        p = text.replace("\\", "/")
        escapes = bool(re.match(r"^[A-Za-z]:", p)) or p.startswith("//")
        parts: list[str] = []
        for seg in p.split("/"):
            if seg in ("", "."):
                continue
            if seg == "..":
                if parts:
                    parts.pop()
                else:
                    escapes = True
            else:
                parts.append(seg)
        if any(seg.startswith("~") for seg in parts[:1]):
            escapes = True
        return PathInfo(raw=text, normalized="/".join(parts), escapes_workspace=escapes)

    def _abs(self, info: PathInfo) -> Path:
        if info.escapes_workspace:
            raise PermissionError(f"path escapes the workspace: {info.raw}")
        path = (self.root / info.normalized).resolve()
        if path != self.root.resolve() and self.root.resolve() not in path.parents:
            raise PermissionError(f"path escapes the workspace: {info.raw}")
        return path

    def list_files(self) -> list[str]:
        out = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file():
                out.append(path.relative_to(self.root).as_posix())
        return out

    def read_file(self, raw: str) -> str:
        info = self.resolve_path(raw)
        path = self._abs(info)
        if not path.is_file():
            raise FileNotFoundError(f"no such file: {info.normalized or info.raw}")
        text = read_text(path)
        if len(text) > MAX_READ_CHARS:
            text = text[:MAX_READ_CHARS] + f"\n... [truncated, file has {len(text)} characters]"
        return text

    def edit_file(self, raw: str, old: str, new: str) -> EditResult:
        info = self.resolve_path(raw)
        self._abs(info)
        if len(new or "") > MAX_EDIT_CHARS:
            return EditResult(False, f"new text is too long ({len(new)} characters, limit {MAX_EDIT_CHARS})")
        return _apply_edit(self.root, info.normalized, old or "", new or "", tolerant=True)

    # plan, diff, apply

    def current_files(self) -> dict[str, str]:
        return root_module_files(self.root)

    def evaluate(self) -> Evaluation:
        files = self.current_files()
        digest = files_digest(files)
        outcome = self.runner.plan(files)
        if outcome.ok and outcome.plan is not None:
            after = state_from_plan(outcome.plan)
            cs = build_changeset(
                self.deployed, after, source="plan", plan_ms=outcome.elapsed_ms, plan_cached=outcome.cached
            )
            return Evaluation(digest, cs, after, None)
        reason = outcome.error or "terraform plan failed"
        cs = changeset_from_hcl(self.deployed, self.deployed_files, files, reason=reason, plan_ms=outcome.elapsed_ms)
        return Evaluation(digest, cs, None, reason)

    def apply(self, evaluation: Evaluation) -> ApplyResult:
        if evaluation.after_state is None:
            return ApplyResult(False, False, f"Apply failed: the configuration does not plan.\n{evaluation.plan_error}")
        files = self.current_files()
        if files_digest(files) != evaluation.files_digest:
            return ApplyResult(False, False, "Apply failed: files changed after the plan was evaluated. Plan again.")
        cs = evaluation.changeset
        if not cs.changes:
            return ApplyResult(True, False, "No changes. Deployed infrastructure already matches the configuration.", cs)
        self.deployed = evaluation.after_state
        self.deployed_files = files
        _write_json(self.state_dir / "deployed.json", self.deployed)
        _write_json(self.state_dir / "deployed_files.json", self.deployed_files)
        s = cs.summary
        return ApplyResult(
            True, True, f"Apply complete: {s.create} created, {s.update} updated, {s.delete} deleted.", cs
        )


def _apply_edit(root: Path, rel: str, old: str, new: str, *, tolerant: bool) -> EditResult:
    path = root / rel
    old = old.replace("\r\n", "\n")
    new = new.replace("\r\n", "\n")
    if not rel:
        return EditResult(False, "path is empty")
    if path.is_dir():
        return EditResult(False, f"{rel} is a directory")
    if not path.exists():
        if old.strip():
            return EditResult(False, f"no such file: {rel}. To create a file, pass an empty old string.")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(new, encoding="utf-8", newline="\n")
        return EditResult(True, f"Created {rel} ({len(new.splitlines())} lines).", created=True)
    text = read_text(path)
    if not old.strip():
        if text.strip():
            return EditResult(False, f"{rel} already exists and is not empty; old must be the exact text to replace.")
        path.write_text(new, encoding="utf-8", newline="\n")
        return EditResult(True, f"Wrote {rel}.")
    count = text.count(old)
    if count == 1:
        path.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")
        return EditResult(True, f"Edited {rel}.")
    if count > 1:
        return EditResult(False, f"old text matches {count} places in {rel}; include more surrounding lines.")
    if not tolerant:
        return EditResult(False, f"old text not found in {rel}")
    return _fuzzy_edit(path, rel, text, old, new)


def _fuzzy_edit(path: Path, rel: str, text: str, old: str, new: str) -> EditResult:
    """Whitespace tolerant fallback: match ``old`` line by line ignoring indentation and spacing."""
    file_lines = text.split("\n")
    old_lines = old.strip("\n").split("\n")
    while old_lines and not old_lines[0].strip():
        old_lines.pop(0)
    while old_lines and not old_lines[-1].strip():
        old_lines.pop()
    target = [_norm_line(line) for line in old_lines]
    if not target:
        return EditResult(False, "old text is blank")
    norm_file = [_norm_line(line) for line in file_lines]
    hits = [i for i in range(len(file_lines) - len(target) + 1) if norm_file[i : i + len(target)] == target]
    if len(hits) == 1:
        start = hits[0]
        delta = _indent(file_lines[start]) - _indent(old_lines[0])
        new_lines = new.strip("\n").split("\n") if new.strip() else []
        if delta > 0:
            new_lines = [(" " * delta + ln) if ln.strip() else ln for ln in new_lines]
        elif delta < 0:
            new_lines = [ln[min(-delta, _indent(ln)) :] for ln in new_lines]
        file_lines[start : start + len(target)] = new_lines
        path.write_text("\n".join(file_lines), encoding="utf-8", newline="\n")
        return EditResult(True, f"Edited {rel} (matched ignoring whitespace).", fuzzy=True)
    if len(hits) > 1:
        return EditResult(False, f"old text matches {len(hits)} places in {rel}; include more surrounding lines.")
    first = old_lines[0].strip()
    close = difflib.get_close_matches(first, [ln.strip() for ln in file_lines if ln.strip()], n=3, cutoff=0.5)
    hint = ""
    if close:
        hint = " Closest lines in the file: " + " | ".join(close)
    return EditResult(False, f"old text not found in {rel}. Read the file again and copy the text exactly.{hint}")
