"""ChangeGate controls ported to AgentSpec predicates for the B1 baseline.

AgentSpec predicates are Python functions ``(user_input, tool_input, intermediate_steps) -> bool``. Each
one below checks one ChangeGate control on the pending change of the current run. They are written in
plain Python against the ChangeSet (they do not call OPA) and share only the parameters in
policies/data.json, so B1 enforces the same controls as P through AgentSpec's own machinery.

What cannot be ported: AgentSpec keeps no state across requests, so the cumulative window budget
(CUM-001, CUM-002) has no predicate. Approvals map to AgentSpec's user_inspection enforcement.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timezone
from typing import Any, Callable

from changegate.config import REPO_ROOT
from changegate.contracts import ChangeSet, ResourceChange, ToolCallRecord

PARAMS: dict[str, Any] = json.loads((REPO_ROOT / "policies" / "data.json").read_text(encoding="utf-8"))["changegate"]["params"]

# The run whose actions are being checked. baselines.agentspec_arm sets it before each request.
CURRENT: dict[str, Any] = {"ctx": None}


def _ctx():
    ctx = CURRENT["ctx"]
    if ctx is None:
        raise RuntimeError("AgentSpec predicates used outside a ChangeGate run")
    return ctx


def _changeset() -> ChangeSet:
    return _ctx().workspace.evaluate().changeset


def _writes(cs: ChangeSet) -> list[ResourceChange]:
    return [c for c in cs.changes if c.action in ("create", "update")]


def _deletes(cs: ChangeSet) -> list[ResourceChange]:
    return [c for c in cs.changes if c.action == "delete"]


def _as_list(value: Any) -> list:
    if isinstance(value, list):
        return value
    return [] if value is None else [value]


def _doc(raw: Any) -> dict:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return {}
    return raw if isinstance(raw, dict) else {}


# Security group ingress


def _rule(cidr: str, protocol: Any, lo: Any, hi: Any) -> tuple[str, str, int, int]:
    proto = str(protocol).lower()
    if proto in ("-1", "all") or not isinstance(lo, int) or not isinstance(hi, int):
        return cidr, proto, 0, 65535
    return cidr, proto, lo, hi


def _ingress(rtype: str, values: dict) -> set[tuple[str, str, int, int]]:
    rules: set[tuple[str, str, int, int]] = set()
    if rtype == "aws_security_group":
        for block in _as_list(values.get("ingress")):
            for cidr in _as_list(block.get("cidr_blocks")) + _as_list(block.get("ipv6_cidr_blocks")):
                rules.add(_rule(cidr, block.get("protocol"), block.get("from_port"), block.get("to_port")))
    elif rtype == "aws_security_group_rule" and values.get("type") == "ingress":
        for cidr in _as_list(values.get("cidr_blocks")) + _as_list(values.get("ipv6_cidr_blocks")):
            rules.add(_rule(cidr, values.get("protocol"), values.get("from_port"), values.get("to_port")))
    elif rtype == "aws_vpc_security_group_ingress_rule":
        for cidr in (values.get("cidr_ipv4"), values.get("cidr_ipv6")):
            if isinstance(cidr, str):
                rules.add(_rule(cidr, values.get("ip_protocol"), values.get("from_port"), values.get("to_port")))
    return rules


def _allowed_public(proto: str, lo: int, hi: int) -> bool:
    allowed = set(PARAMS["public_ingress_allowed_ports"])
    return proto not in ("-1", "all") and all(p in allowed for p in range(lo, hi + 1)) if hi - lo < 1000 else False


def check_public_ingress(cs: ChangeSet) -> list[str]:
    out = []
    for c in _writes(cs):
        new = _ingress(c.type, c.after or {}) - _ingress(c.type, c.before or {})
        for cidr, proto, lo, hi in sorted(new):
            if cidr in PARAMS["public_cidrs"] and not _allowed_public(proto, lo, hi):
                out.append(f"{c.address} opens ports {lo}-{hi} to {cidr}")
    return out


def check_public_bucket(cs: ChangeSet) -> list[str]:
    out = []
    flags = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
    for c in _writes(cs):
        after = c.after or {}
        if c.type in ("aws_s3_bucket_acl", "aws_s3_bucket") and after.get("acl") in PARAMS["public_acls"]:
            out.append(f"{c.address} sets a public ACL")
        if c.type == "aws_s3_bucket_acl":
            for acp in _as_list(after.get("access_control_policy")):
                for grant in _as_list(acp.get("grant")):
                    for grantee in _as_list(grant.get("grantee")):
                        if grantee.get("uri") in PARAMS["public_grantee_uris"]:
                            out.append(f"{c.address} grants a public group")
        if c.type == "aws_s3_bucket_policy":
            for s in _as_list(_doc(after.get("policy")).get("Statement")):
                if s.get("Effect") == "Allow" and _public_principal(s.get("Principal")):
                    out.append(f"{c.address} allows Principal *")
        if c.type == "aws_s3_bucket_public_access_block" and any(after.get(f) is False for f in flags):
            out.append(f"{c.address} weakens the public access block")
    out += [f"{c.address} deletes the public access block" for c in _deletes(cs) if c.type == "aws_s3_bucket_public_access_block"]
    return out


def _public_principal(p: Any) -> bool:
    if p == "*":
        return True
    return isinstance(p, dict) and "*" in _as_list(p.get("AWS"))


def _sse(values: dict) -> set[str]:
    return {
        d.get("sse_algorithm")
        for r in _as_list(values.get("rule"))
        for d in _as_list(r.get("apply_server_side_encryption_by_default"))
        if d.get("sse_algorithm")
    }


def check_weak_encryption(cs: ChangeSet) -> list[str]:
    out = []
    sse_type = "aws_s3_bucket_server_side_encryption_configuration"
    out += [f"{c.address} removes bucket encryption" for c in _deletes(cs) if c.type == sse_type]
    for c in _writes(cs):
        if c.type == sse_type:
            after, before = _sse(c.after or {}), _sse(c.before or {})
            if any(a not in PARAMS["allowed_sse_algorithms"] for a in after):
                out.append(f"{c.address} uses a disallowed algorithm")
            if c.action == "update" and before & set(PARAMS["kms_sse_algorithms"]) and not after & set(PARAMS["kms_sse_algorithms"]):
                out.append(f"{c.address} downgrades from KMS encryption")
        if c.type in ("aws_ebs_volume", "aws_efs_file_system") and (c.after or {}).get("encrypted") is False:
            out.append(f"{c.address} is unencrypted")
    return out


def _wild_action(a: Any) -> bool:
    return isinstance(a, str) and (a == "*" or a.endswith(":*"))


def check_iam_wildcard(cs: ChangeSet) -> list[str]:
    out = []
    for c in _writes(cs):
        after = c.after or {}
        if c.type in PARAMS["iam_policy_types"]:
            for s in _as_list(_doc(after.get("policy")).get("Statement")):
                wild_a = "NotAction" in s or any(_wild_action(a) for a in _as_list(s.get("Action")))
                wild_r = "NotResource" in s or "*" in _as_list(s.get("Resource"))
                if s.get("Effect") == "Allow" and wild_a and wild_r:
                    out.append(f"{c.address} allows wildcard actions on all resources")
        if c.type in PARAMS["iam_attachment_types"] and after.get("policy_arn") in PARAMS["admin_policy_arns"]:
            out.append(f"{c.address} attaches an administrator policy")
        if c.type == "aws_iam_role":
            for s in _as_list(_doc(after.get("assume_role_policy")).get("Statement")):
                if s.get("Effect") == "Allow" and _public_principal(s.get("Principal")):
                    out.append(f"{c.address} trusts any principal")
    return out


def check_db_exposed(cs: ChangeSet) -> list[str]:
    out = []
    for c in _writes(cs):
        if c.type in ("aws_db_instance", "aws_rds_cluster"):
            if (c.after or {}).get("publicly_accessible") is True:
                out.append(f"{c.address} becomes publicly accessible")
            if (c.after or {}).get("storage_encrypted") is False:
                out.append(f"{c.address} stores data unencrypted")
    return out


def _is_audit_bucket(values: dict, refs: dict) -> bool:
    deployed = _ctx().workspace.deployed
    audit = set(PARAMS["audit_classifications"])
    for address, res in deployed.items():
        tags = (res.get("values") or {}).get("tags") or {}
        if tags.get("data_classification") not in audit:
            continue
        if (res.get("values") or {}).get("bucket") == values.get("bucket") or address in _as_list(refs.get("bucket")):
            return True
    return False


def check_audit_tamper(cs: ChangeSet) -> list[str]:
    out = []
    for c in _writes(cs):
        if c.type == "aws_s3_bucket_versioning" and _is_audit_bucket(c.after or {}, c.references):
            if any(v.get("status") != "Enabled" for v in _as_list((c.after or {}).get("versioning_configuration"))):
                out.append(f"{c.address} turns off audit bucket versioning")
    for c in _deletes(cs):
        if c.type in ("aws_s3_bucket_versioning", "aws_s3_bucket_object_lock_configuration") and _is_audit_bucket(c.before or {}, c.references):
            out.append(f"{c.address} removes audit bucket protection")
    return out


def check_kms_weakened(cs: ChangeSet) -> list[str]:
    out = []
    for c in _writes(cs):
        if c.type == "aws_kms_key":
            if (c.after or {}).get("enable_key_rotation") is False:
                out.append(f"{c.address} turns off key rotation")
            if (c.after or {}).get("is_enabled") is False:
                out.append(f"{c.address} disables the key")
    return out


def check_mass_delete(cs: ChangeSet) -> list[str]:
    n = len(_deletes(cs))
    return [f"the change deletes {n} resources"] if n > PARAMS["max_deletes_per_change"] else []


def check_critical_delete(cs: ChangeSet) -> list[str]:
    today = _ctx().request.timestamp.astimezone(timezone.utc).strftime("%Y-%m-%d")
    key, values = PARAMS["critical_tag"]["key"], PARAMS["critical_tag"]["values"]
    out = []
    for c in _deletes(cs):
        tags = (c.before or {}).get("tags") or {}
        retained = tags.get(PARAMS["retention_tag"])
        if tags.get(key) in values or (isinstance(retained, str) and len(retained) == 10 and retained >= today):
            out.append(f"{c.address} is critical or retained")
    return out


def check_stateful_replace(cs: ChangeSet) -> list[str]:
    out = []
    for c in cs.changes:
        if c.action == "update" and c.type in PARAMS["stateful_types"]:
            forced = set(c.changed_attributes) & set(PARAMS["force_new_attributes"].get(c.type, []))
            if forced:
                out.append(f"{c.address} would be replaced ({', '.join(sorted(forced))})")
    return out


def check_large_change(cs: ChangeSet) -> list[str]:
    n = len(cs.changes)
    return [f"the change touches {n} resources"] if n > PARAMS["max_changes_per_change"] else []


def check_outside_window(cs: ChangeSet) -> list[str]:
    if not cs.changes:
        return []
    window = PARAMS["change_window"]
    now = _ctx().request.timestamp.astimezone(timezone.utc)
    start_h, start_m = (int(x) for x in window["start"].split(":"))
    end_h, end_m = (int(x) for x in window["end"].split(":"))
    minutes = now.hour * 60 + now.minute
    inside = now.strftime("%A") == window["weekday"] and start_h * 60 + start_m <= minutes < end_h * 60 + end_m
    return [] if inside else [f"{now:%A %H:%M} UTC is outside the change window"]


def check_privileged_change(cs: ChangeSet) -> list[str]:
    out = []
    for c in cs.changes:
        attrs = PARAMS["approval_required_attributes"].get(c.type, [])
        if c.type in PARAMS["approval_required_types"] or set(c.changed_attributes) & set(attrs):
            out.append(f"{c.address} is a privileged change")
    return out


def check_protected_path(tool_input: Any) -> list[str]:
    raw = str((tool_input or {}).get("path") or (tool_input or {}).get("file_path") or "")
    info = _ctx().workspace.resolve_path(raw)
    if info.escapes_workspace:
        return [f"{raw} escapes the repository"]
    target = info.normalized.lower()
    for prefix in PARAMS["protected_paths"]:
        p = prefix.lower()
        if target.startswith(p) or target == p.rstrip("/"):
            return [f"{info.normalized} is a protected path"]
    return []


@dataclass(frozen=True)
class Control:
    predicate: str  # name registered in AgentSpec's grammar and predicate table
    rule_id: str
    trigger: str  # tool name the AgentSpec rule triggers on
    enforcement: str  # AgentSpec enforcement
    effect: str  # how the intervention is recorded: deny or require_approval
    check: Callable[..., list[str]]
    on_input: bool = False  # True when the check reads the tool input instead of the ChangeSet


CONTROLS = [
    Control("cg_public_ingress", "SEC-001", "terraform_apply", "llm_self_reflect", "deny", check_public_ingress),
    Control("cg_public_bucket", "SEC-002", "terraform_apply", "llm_self_reflect", "deny", check_public_bucket),
    Control("cg_weak_encryption", "SEC-004", "terraform_apply", "llm_self_reflect", "deny", check_weak_encryption),
    Control("cg_iam_wildcard", "SEC-005", "terraform_apply", "llm_self_reflect", "deny", check_iam_wildcard),
    Control("cg_db_exposed", "SEC-006", "terraform_apply", "llm_self_reflect", "deny", check_db_exposed),
    Control("cg_audit_tamper", "SEC-007", "terraform_apply", "llm_self_reflect", "deny", check_audit_tamper),
    Control("cg_kms_weakened", "SEC-008", "terraform_apply", "llm_self_reflect", "deny", check_kms_weakened),
    Control("cg_mass_delete", "BR-001", "terraform_apply", "llm_self_reflect", "deny", check_mass_delete),
    Control("cg_critical_delete", "BR-002", "terraform_apply", "llm_self_reflect", "deny", check_critical_delete),
    Control("cg_stateful_replace", "BR-003", "terraform_apply", "llm_self_reflect", "deny", check_stateful_replace),
    Control("cg_large_change", "BR-004", "terraform_apply", "llm_self_reflect", "deny", check_large_change),
    Control("cg_outside_window", "CW-001", "terraform_apply", "user_inspection", "require_approval", check_outside_window),
    Control("cg_privileged_change", "SOD-001", "terraform_apply", "user_inspection", "require_approval", check_privileged_change),
    Control("cg_protected_path", "PP-001", "edit_file", "stop", "deny", check_protected_path, on_input=True),
]

PREDICATE_NAMES = [c.predicate for c in CONTROLS]


def _record(control: Control, tool: str, messages: list[str]) -> None:
    """Log an AgentSpec intervention the same way the PEP logs a decision."""
    ctx = _ctx()
    ctx.records.append(
        ToolCallRecord(
            step=ctx.step,
            tool=tool,
            decision=control.effect,
            rule_ids=[control.rule_id],
            guard="agentspec",
            executed=False,
            ok=False,
            observation="; ".join(messages)[:600],
        )
    )
    ctx.audit.append(
        "decision",
        request_id=ctx.request.id,
        session_id=ctx.session_id,
        sim_time=ctx.request.timestamp,
        action=tool,
        payload={"guard": "agentspec", "predicate": control.predicate, "rule_id": control.rule_id,
                 "enforcement": control.enforcement, "messages": messages},
    )


def make_predicate(control: Control) -> Callable[[Any, Any, Any], bool]:
    def predicate(user_input: Any, tool_input: Any, intermediate_steps: Any) -> bool:
        messages = control.check(tool_input) if control.on_input else control.check(_changeset())
        if messages:
            _record(control, control.trigger, messages)
        return bool(messages)

    predicate.__name__ = control.predicate
    return predicate


def rule_text(control: Control) -> str:
    """The AgentSpec rule for one control, in AgentSpec's own DSL."""
    return (
        f"rule @{control.predicate.removeprefix('cg_')}\n"
        f"trigger\n    {control.trigger}\n"
        f"check\n    {control.predicate}\n"
        f"enforce\n    {control.enforcement}\n"
        "end\n"
    )
