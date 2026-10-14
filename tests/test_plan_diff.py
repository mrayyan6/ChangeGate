import shutil

import pytest

from changegate.config import REPO_ROOT, load_config
from changegate.plan_diff import build_changeset, changeset_from_hcl, diff_states, hcl_state, state_from_plan
from changegate.terraform import TerraformRunner
from changegate.workspace import Workspace


def _res(rtype, name, values, refs=None):
    return {"type": rtype, "name": name, "values": values, "references": refs or {}, "unknown": []}


def test_diff_detects_create_update_delete():
    before = {
        "aws_s3_bucket.a": _res("aws_s3_bucket", "a", {"bucket": "a", "tags": {"x": "1"}}),
        "aws_s3_bucket.b": _res("aws_s3_bucket", "b", {"bucket": "b"}),
    }
    after = {
        "aws_s3_bucket.a": _res("aws_s3_bucket", "a", {"bucket": "a", "tags": {"x": "2"}}),
        "aws_s3_bucket.c": _res("aws_s3_bucket", "c", {"bucket": "c", "force_destroy": None}),
    }
    changes = {c.address: c for c in diff_states(before, after)}
    assert changes["aws_s3_bucket.a"].action == "update"
    assert changes["aws_s3_bucket.a"].changed_attributes == ["tags"]
    assert changes["aws_s3_bucket.b"].action == "delete"
    assert changes["aws_s3_bucket.b"].after is None
    assert changes["aws_s3_bucket.c"].action == "create"
    assert changes["aws_s3_bucket.c"].changed_attributes == ["bucket"]


def test_diff_sees_reference_only_changes_and_unknowns():
    before = {"aws_db_instance.main": _res("aws_db_instance", "main", {"x": 1}, {"kms_key_id": ["aws_kms_key.data"]})}
    after = {"aws_db_instance.main": _res("aws_db_instance", "main", {"x": 1}, {"kms_key_id": ["aws_kms_key.other"]})}
    (change,) = diff_states(before, after)
    assert change.changed_attributes == ["kms_key_id"]
    # a value that becomes unknown (missing from planned values) counts as changed
    after2 = {"aws_db_instance.main": _res("aws_db_instance", "main", {}, {"kms_key_id": ["aws_kms_key.data"]})}
    (change2,) = diff_states(before, after2)
    assert change2.changed_attributes == ["x"]


def test_changeset_digest_is_stable_and_summary_counts():
    before = {"a.b": _res("a_b", "b", {"v": 1})}
    after = {"a.b": _res("a_b", "b", {"v": 2}), "a.c": _res("a_c", "c", {"v": 3})}
    cs1 = build_changeset(before, after, source="plan")
    cs2 = build_changeset(before, after, source="plan")
    assert cs1.digest == cs2.digest
    assert (cs1.summary.create, cs1.summary.update, cs1.summary.delete) == (1, 1, 0)
    assert build_changeset(before, before, source="plan").changes == []


def test_state_from_plan_reads_values_refs_and_unknowns():
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {"address": "aws_s3_bucket.x", "mode": "managed", "type": "aws_s3_bucket", "name": "x", "values": {"bucket": "x"}},
                    {"address": "data.aws_caller_identity.me", "mode": "data", "type": "aws_caller_identity", "name": "me", "values": {}},
                ]
            }
        },
        "resource_changes": [{"address": "aws_s3_bucket.x", "after_unknown": {"id": True, "tags": False}}],
        "configuration": {
            "root_module": {
                "resources": [
                    {"address": "aws_s3_bucket.x", "mode": "managed", "expressions": {"bucket": {"references": ["local.name", "aws_kms_key.k.arn", "aws_kms_key.k"]}}}
                ]
            }
        },
    }
    state = state_from_plan(plan)
    assert list(state) == ["aws_s3_bucket.x"]
    assert state["aws_s3_bucket.x"]["unknown"] == ["id"]
    assert state["aws_s3_bucket.x"]["references"] == {"bucket": ["aws_kms_key.k", "local.name"]}


HCL_BEFORE = {
    "main.tf": """
variable "window" {
  default = "03:00-03:30"
}
locals {
  prefix = "fintech"
}
resource "aws_s3_bucket" "logs" {
  bucket = "${local.prefix}-logs"
}
resource "aws_db_instance" "db" {
  backup_window = var.window
  publicly_accessible = false
}
"""
}


def test_hcl_state_resolves_vars_and_locals():
    state = hcl_state(HCL_BEFORE)
    assert state["aws_s3_bucket.logs"]["values"]["bucket"] == "fintech-logs"
    assert state["aws_db_instance.db"]["values"]["backup_window"] == "03:00-03:30"
    assert state["aws_db_instance.db"]["values"]["publicly_accessible"] is False


def test_hcl_fallback_changeset_overlays_changed_attributes():
    deployed = {
        "aws_s3_bucket.logs": _res("aws_s3_bucket", "logs", {"bucket": "fintech-logs", "force_destroy": False}),
        "aws_db_instance.db": _res(
            "aws_db_instance", "db", {"backup_window": "03:00-03:30", "publicly_accessible": False, "engine": "postgres"}
        ),
    }
    after_files = {
        "main.tf": HCL_BEFORE["main.tf"]
        .replace("publicly_accessible = false", "publicly_accessible = true")
        .replace('resource "aws_s3_bucket" "logs" {\n  bucket = "${local.prefix}-logs"\n}\n', "")
    }
    cs = changeset_from_hcl(deployed, HCL_BEFORE, after_files, reason="plan failed: test")
    assert cs.source == "hcl_fallback" and cs.fallback_reason == "plan failed: test"
    changes = {c.address: c for c in cs.changes}
    assert changes["aws_s3_bucket.logs"].action == "delete"
    db = changes["aws_db_instance.db"]
    assert db.action == "update" and db.changed_attributes == ["publicly_accessible"]
    assert db.after["publicly_accessible"] is True and db.after["engine"] == "postgres"


def test_hcl_fallback_reports_parse_errors():
    cs = changeset_from_hcl({}, HCL_BEFORE, {"main.tf": 'resource "x" {'}, reason="plan failed")
    assert cs.changes == [] and any("HCL parse failed" in e for e in cs.errors)


requires_terraform = pytest.mark.skipif(shutil.which("terraform") is None, reason="terraform not installed")


@requires_terraform
@pytest.mark.slow
def test_workspace_offline_plan_edit_apply(tmp_path):
    cfg = load_config()
    runner = TerraformRunner(cfg)
    ws = Workspace.create(REPO_ROOT / cfg.terraform.env_dir, tmp_path / "s1", runner)
    assert len(ws.deployed) == 30
    assert ws.evaluate().changeset.changes == []

    edit = ws.edit_file(
        "security_groups.tf",
        '  egress {\n    description = "Administration traffic into the VPC"',
        '  ingress {\n    description = "SSH from the corporate VPN"\n    from_port   = 22\n    to_port     = 22\n'
        '    protocol    = "tcp"\n    cidr_blocks = ["10.50.0.0/16"]\n  }\n\n'
        '  egress {\n    description = "Administration traffic into the VPC"',
    )
    assert edit.ok, edit.message
    ev = ws.evaluate()
    assert ev.changeset.source == "plan"
    (change,) = ev.changeset.changes
    assert change.address == "aws_security_group.bastion" and change.action == "update"
    assert "ingress" in change.changed_attributes
    assert change.after["ingress"][0]["cidr_blocks"] == ["10.50.0.0/16"]

    result = ws.apply(ev)
    assert result.ok and result.applied
    assert ws.evaluate().changeset.changes == []

    # a config that does not plan falls back to HCL parsing and records why
    bad = ws.edit_file("storage.tf", 'resource "aws_s3_bucket" "legacy_tmp" {', 'resource "aws_s3_bucket" "legacy_tmp" {\n  no_such_argument = 1')
    assert bad.ok
    ev2 = ws.evaluate()
    assert ev2.changeset.source == "hcl_fallback" and ev2.after_state is None
    assert ev2.changeset.fallback_reason
    assert not ws.apply(ev2).ok


def test_resolve_path_flags_escapes(tmp_path):
    ws = object.__new__(Workspace)
    assert ws.resolve_path("./policies/../README.md").normalized == "README.md"
    assert ws.resolve_path("..\\secrets.txt").escapes_workspace
    assert ws.resolve_path("C:/Windows/win.ini").escapes_workspace
    assert ws.resolve_path("/approvals/CHG-1.yaml").normalized == "approvals/CHG-1.yaml"
