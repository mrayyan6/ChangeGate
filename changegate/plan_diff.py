"""Build normalized ChangeSets from Terraform planned values, with an HCL fallback.

A *state* maps a resource address to ``{"type", "name", "values", "references", "unknown"}``.
``values`` come from ``planned_values`` (attributes known at plan time), ``references`` from the plan's
``configuration`` section and ``unknown`` from ``resource_changes[].change.after_unknown``.

The ChangeSet is the diff between the deployed state and the proposed state. Terraform's own actions
are not used because the offline plans start from empty state, where every resource is a create.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any

from changegate.contracts import ChangeSet, ChangeSummary, ResourceChange

State = dict[str, dict[str, Any]]

_MISSING = object()
_INDEX_RE = re.compile(r"\[[^\]]*\]$")
_META_ARGS = {"count", "for_each", "depends_on", "lifecycle", "provider", "provisioner", "connection"}


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def sha256_json(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def state_digest(state: State) -> str:
    return sha256_json(
        {addr: {"values": r.get("values", {}), "references": r.get("references", {})} for addr, r in state.items()}
    )


# Planned values


def _base_address(address: str) -> str:
    return _INDEX_RE.sub("", address)


def _collect_refs(expr: Any) -> list[str]:
    found: list[str] = []
    if isinstance(expr, dict):
        refs = expr.get("references")
        if isinstance(refs, list):
            found.extend(str(r) for r in refs)
        for key, value in expr.items():
            if key != "references":
                found.extend(_collect_refs(value))
    elif isinstance(expr, list):
        for item in expr:
            found.extend(_collect_refs(item))
    return found


def _normalize_refs(refs: list[str]) -> list[str]:
    """Keep resource addresses (type.name), variables and locals; drop attribute suffixed duplicates."""
    out: set[str] = set()
    for ref in refs:
        parts = ref.split(".")
        if parts[0] in ("var", "local") and len(parts) >= 2:
            out.add(".".join(parts[:2]))
        elif parts[0] == "module" and len(parts) >= 2:
            out.add(".".join(parts[:2]))
        elif parts[0] == "data" and len(parts) >= 3:
            out.add(".".join(parts[:3]))
        elif len(parts) >= 2 and "_" in parts[0]:
            out.add(_base_address(".".join(parts[:2])))
    return sorted(out)


def _config_references(module: dict[str, Any], prefix: str, out: dict[str, dict[str, list[str]]]) -> None:
    for res in module.get("resources", []) or []:
        if res.get("mode", "managed") != "managed":
            continue
        attrs: dict[str, list[str]] = {}
        for attr, expr in (res.get("expressions") or {}).items():
            refs = _normalize_refs(_collect_refs(expr))
            if refs:
                attrs[attr] = refs
        out[prefix + res["address"]] = attrs
    for name, call in (module.get("module_calls") or {}).items():
        _config_references(call.get("module") or {}, f"{prefix}module.{name}.", out)


def _unknown_attrs(after_unknown: Any) -> list[str]:
    if not isinstance(after_unknown, dict):
        return []

    def has_true(value: Any) -> bool:
        if value is True:
            return True
        if isinstance(value, dict):
            return any(has_true(v) for v in value.values())
        if isinstance(value, list):
            return any(has_true(v) for v in value)
        return False

    return sorted(k for k, v in after_unknown.items() if has_true(v))


def _walk_planned(module: dict[str, Any], out: State) -> None:
    for res in module.get("resources", []) or []:
        if res.get("mode", "managed") != "managed":
            continue
        out[res["address"]] = {
            "type": res["type"],
            "name": res["name"],
            "values": res.get("values") or {},
        }
    for child in module.get("child_modules", []) or []:
        _walk_planned(child, out)


def state_from_plan(plan: dict[str, Any]) -> State:
    state: State = {}
    _walk_planned((plan.get("planned_values") or {}).get("root_module") or {}, state)
    refs: dict[str, dict[str, list[str]]] = {}
    _config_references((plan.get("configuration") or {}).get("root_module") or {}, "", refs)
    unknown = {rc["address"]: _unknown_attrs(rc.get("after_unknown")) for rc in plan.get("resource_changes", [])}
    for address, entry in state.items():
        entry["references"] = refs.get(_base_address(address), {})
        entry["unknown"] = unknown.get(address, [])
    return state


# Diff


def _changed_attributes(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    bv, av = before.get("values", {}), after.get("values", {})
    br, ar = before.get("references", {}), after.get("references", {})
    keys = set(bv) | set(av) | set(br) | set(ar)
    changed = []
    for key in sorted(keys):
        if canonical_json(bv.get(key, None)) != canonical_json(av.get(key, None)) or (key in bv) != (key in av):
            changed.append(key)
        elif br.get(key, []) != ar.get(key, []):
            changed.append(key)
    return changed


def diff_states(before: State, after: State) -> list[ResourceChange]:
    changes: list[ResourceChange] = []
    for address in sorted(set(before) | set(after)):
        b, a = before.get(address), after.get(address)
        if b is None and a is not None:
            values = a.get("values", {})
            changes.append(
                ResourceChange(
                    address=address,
                    type=a["type"],
                    name=a["name"],
                    action="create",
                    changed_attributes=sorted(k for k, v in values.items() if v not in (None, [], {})),
                    after=values,
                    unknown_after=a.get("unknown", []),
                    references=a.get("references", {}),
                )
            )
        elif a is None and b is not None:
            changes.append(
                ResourceChange(
                    address=address,
                    type=b["type"],
                    name=b["name"],
                    action="delete",
                    before=b.get("values", {}),
                    references=b.get("references", {}),
                )
            )
        elif a is not None and b is not None:
            changed = _changed_attributes(b, a)
            if not changed:
                continue
            changes.append(
                ResourceChange(
                    address=address,
                    type=a["type"],
                    name=a["name"],
                    action="update",
                    changed_attributes=changed,
                    before=b.get("values", {}),
                    after=a.get("values", {}),
                    unknown_after=a.get("unknown", []),
                    references=a.get("references", {}),
                )
            )
    return changes


def summarize(changes: list[ResourceChange]) -> ChangeSummary:
    summary = ChangeSummary()
    for change in changes:
        setattr(summary, change.action, getattr(summary, change.action) + 1)
    return summary


def changes_digest(changes: list[ResourceChange]) -> str:
    return sha256_json(
        [c.model_dump(include={"address", "action", "before", "after", "references"}) for c in changes]
    )


def build_changeset(
    before: State,
    after: State,
    *,
    source: str,
    fallback_reason: str | None = None,
    plan_ms: float = 0.0,
    plan_cached: bool = False,
    errors: list[str] | None = None,
) -> ChangeSet:
    changes = diff_states(before, after)
    return ChangeSet(
        source=source,
        fallback_reason=fallback_reason,
        changes=changes,
        summary=summarize(changes),
        base_digest=state_digest(before),
        target_digest=state_digest(after),
        digest=changes_digest(changes),
        plan_ms=round(plan_ms, 1),
        plan_cached=plan_cached,
        errors=errors or [],
    )


# HCL fallback


def _unquote(text: str) -> str:
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        try:
            return json.loads(text)
        except ValueError:
            return text[1:-1]
    return text


def _normalize_hcl(value: Any) -> Any:
    if isinstance(value, dict):
        return {_unquote(k): _normalize_hcl(v) for k, v in value.items() if not (k.startswith("__") and k.endswith("__"))}
    if isinstance(value, list):
        return [_normalize_hcl(v) for v in value]
    if isinstance(value, str):
        return _unquote(value)
    return value


_WHOLE_REF = re.compile(r"^\$\{\s*(var|local)\.([A-Za-z0-9_-]+)\s*\}$")
_INNER_REF = re.compile(r"\$\{\s*(var|local)\.([A-Za-z0-9_-]+)\s*\}")
_EXPR = re.compile(r"\$\{([^}]*)\}")
_RES_TOKEN = re.compile(r"\b([a-z][a-z0-9]*_[a-z0-9_]+)\.([A-Za-z0-9_-]+)")
_VAR_TOKEN = re.compile(r"\b(var|local)\.([A-Za-z0-9_-]+)")


def _resolve(value: Any, ctx: dict[str, dict[str, Any]], depth: int = 0) -> Any:
    if depth > 8:
        return value
    if isinstance(value, dict):
        return {k: _resolve(v, ctx, depth) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve(v, ctx, depth) for v in value]
    if not isinstance(value, str):
        return value
    whole = _WHOLE_REF.match(value)
    if whole:
        kind, name = whole.groups()
        if name in ctx[kind]:
            return _resolve(ctx[kind][name], ctx, depth + 1)
        return value

    def repl(match: re.Match) -> str:
        kind, name = match.groups()
        target = ctx[kind].get(name, _MISSING)
        if target is _MISSING:
            return match.group(0)
        target = _resolve(target, ctx, depth + 1)
        if isinstance(target, bool):
            return "true" if target else "false"
        if isinstance(target, (str, int, float)):
            return str(target)
        return match.group(0)

    return _INNER_REF.sub(repl, value)


def _refs_in(value: Any) -> list[str]:
    refs: set[str] = set()
    if isinstance(value, dict):
        for v in value.values():
            refs.update(_refs_in(v))
    elif isinstance(value, list):
        for v in value:
            refs.update(_refs_in(v))
    elif isinstance(value, str):
        for expr in _EXPR.findall(value):
            refs.update(f"{t}.{n}" for t, n in _RES_TOKEN.findall(expr) if t not in ("var", "local"))
            refs.update(f"{k}.{n}" for k, n in _VAR_TOKEN.findall(expr))
    return sorted(refs)


def parse_hcl(files: dict[str, str]) -> dict[str, Any]:
    """Parse root module ``.tf`` files with python-hcl2. Raises on any parse error."""
    import hcl2  # imported lazily: only the fallback path needs it

    resources: dict[str, dict[str, Any]] = {}
    variables: dict[str, Any] = {}
    local_values: dict[str, Any] = {}
    for name in sorted(files):
        if not name.endswith(".tf"):
            continue
        doc = _normalize_hcl(hcl2.loads(files[name]))
        for block in doc.get("variable", []) or []:
            for var_name, body in block.items():
                if isinstance(body, dict) and "default" in body:
                    variables[var_name] = body["default"]
        for block in doc.get("locals", []) or []:
            if isinstance(block, dict):
                local_values.update(block)
        for block in doc.get("resource", []) or []:
            for rtype, named in block.items():
                for rname, body in (named or {}).items():
                    body = {k: v for k, v in (body or {}).items() if k not in _META_ARGS}
                    resources[f"{rtype}.{rname}"] = {"type": rtype, "name": rname, "values": body}
    return {"resources": resources, "variables": variables, "locals": local_values}


def hcl_state(files: dict[str, str]) -> State:
    parsed = parse_hcl(files)
    ctx = {"var": parsed["variables"], "local": parsed["locals"]}
    state: State = {}
    for address, res in parsed["resources"].items():
        values = _resolve(res["values"], ctx)
        refs = {k: r for k, v in res["values"].items() if (r := _refs_in(v))}
        state[address] = {"type": res["type"], "name": res["name"], "values": values, "references": refs, "unknown": []}
    return state


def changeset_from_hcl(
    deployed: State,
    deployed_files: dict[str, str],
    current_files: dict[str, str],
    *,
    reason: str,
    plan_ms: float = 0.0,
) -> ChangeSet:
    """Fallback when the plan fails: detect changed resource blocks in the HCL source.

    Unchanged resources keep their exact deployed planned values. Changed resources start from the
    deployed values with the changed attributes overlaid from the parsed source. New resources use the
    parsed source as is. Expressions that cannot be resolved stay as ``${...}`` strings.
    """
    try:
        before_src = hcl_state(deployed_files)
        after_src = hcl_state(current_files)
    except Exception as exc:  # parse errors from python-hcl2 or lark
        return ChangeSet(
            source="hcl_fallback",
            fallback_reason=reason,
            base_digest=state_digest(deployed),
            target_digest="",
            digest=sha256_json(["unparseable", reason]),
            plan_ms=round(plan_ms, 1),
            errors=[reason, f"HCL parse failed: {exc}"],
        )

    after: State = {}
    for address, src in after_src.items():
        old_src = before_src.get(address)
        live = deployed.get(address)
        if old_src is not None and live is not None:
            if canonical_json(old_src["values"]) == canonical_json(src["values"]):
                after[address] = live
                continue
            merged = copy.deepcopy(live)
            merged.setdefault("references", {})
            for key in set(old_src["values"]) | set(src["values"]):
                if canonical_json(old_src["values"].get(key)) == canonical_json(src["values"].get(key)):
                    continue
                merged["values"][key] = src["values"].get(key)
                if key in src["references"]:
                    merged["references"][key] = src["references"][key]
                else:
                    merged["references"].pop(key, None)
            after[address] = merged
        else:
            after[address] = src
    return build_changeset(deployed, after, source="hcl_fallback", fallback_reason=reason, plan_ms=plan_ms, errors=[reason])
