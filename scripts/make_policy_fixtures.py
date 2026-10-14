"""Generate realistic PolicyInput fixtures for the Rego tests from real offline plans of Env A.

Each case applies literal edits to a fresh copy of envs/fintech, plans it and writes the PolicyInput for
a terraform_apply to policies/testdata/<case>.json, wrapped as {"<case>": <input>} so that
`opa test policies` exposes it as data.testdata.<case>. The runtime OPA client ignores testdata/.

Usage (PowerShell, from the repo root):
    .\\.venv\\Scripts\\python.exe scripts\\make_policy_fixtures.py
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from changegate.config import load_config  # noqa: E402
from changegate.contracts import ChangeRequest, SessionState, Ticket, WindowTotals  # noqa: E402
from changegate.policy_input import build_policy_input  # noqa: E402
from changegate.terraform import TerraformRunner  # noqa: E402
from changegate.workspace import Workspace  # noqa: E402

SAT = datetime(2026, 10, 17, 2, 30, tzinfo=timezone.utc)  # inside the Saturday change window

BASTION_EGRESS = '  egress {\n    description = "Administration traffic into the VPC"'


def ssh_rule(cidr: str) -> str:
    return (
        "  ingress {\n"
        '    description = "SSH access"\n'
        "    from_port   = 22\n"
        "    to_port     = 22\n"
        '    protocol    = "tcp"\n'
        f'    cidr_blocks = ["{cidr}"]\n'
        "  }\n\n" + BASTION_EGRESS
    )


def block(rtype: str, name: str) -> str:
    return f'resource "{rtype}" "{name}" {{'


def remove_resource(text: str, rtype: str, name: str) -> tuple[str, str]:
    """Return (old, new) that deletes one resource block, found by brace matching."""
    start = text.index(block(rtype, name))
    depth, i = 0, start
    while True:
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    return text[start : i + 1], ""


ACL = '\nresource "aws_s3_bucket_acl" "reports" {{\n  bucket = aws_s3_bucket.reports.bucket\n  acl    = "{acl}"\n}}\n'
VERSIONING_REPORTS = (
    '\nresource "aws_s3_bucket_versioning" "reports" {\n  bucket = aws_s3_bucket.reports.bucket\n\n'
    '  versioning_configuration {\n    status = "Enabled"\n  }\n}\n'
)
ATTACH_CI = (
    '\nresource "aws_iam_role_policy_attachment" "ci_reports_read" {\n  role       = aws_iam_role.ci_deploy.name\n'
    "  policy_arn = aws_iam_policy.app_s3_read.arn\n}\n"
)

# case name -> list of edits; an edit is (file, old, new) or ("delete", type, name, file)
CASES: dict[str, list[tuple]] = {
    "noop": [],
    "bastion_ssh_world": [("security_groups.tf", BASTION_EGRESS, ssh_rule("0.0.0.0/0"))],
    "bastion_ssh_vpn": [("security_groups.tf", BASTION_EGRESS, ssh_rule("10.50.0.0/16"))],
    "reports_acl_public": [("storage.tf", None, ACL.format(acl="public-read"))],
    "reports_acl_private": [("storage.tf", None, ACL.format(acl="private"))],
    "reports_pab_off": [
        ("storage.tf", "  bucket                  = aws_s3_bucket.reports.bucket\n  block_public_acls       = true",
         "  bucket                  = aws_s3_bucket.reports.bucket\n  block_public_acls       = false")
    ],
    "customer_sse_deleted": [("delete", "aws_s3_bucket_server_side_encryption_configuration", "customer_data", "storage.tf")],
    "customer_sse_bucket_key": [("storage.tf", "    bucket_key_enabled = false", "    bucket_key_enabled = true")],
    "iam_wildcard": [
        ("iam.tf", '      Sid      = "ReadReports"\n      Effect   = "Allow"\n      Action   = ["s3:GetObject"]\n      Resource = ["arn:aws:s3:::fintech-prod-reports/*"]',
         '      Sid      = "ReadReports"\n      Effect   = "Allow"\n      Action   = "*"\n      Resource = "*"')
    ],
    "iam_list_bucket": [
        ("iam.tf", '      Action   = ["s3:GetObject"]\n      Resource = ["arn:aws:s3:::fintech-prod-reports/*"]',
         '      Action   = ["s3:GetObject", "s3:ListBucket"]\n      Resource = ["arn:aws:s3:::fintech-prod-reports", "arn:aws:s3:::fintech-prod-reports/*"]')
    ],
    "rds_public": [("database.tf", "  publicly_accessible    = false", "  publicly_accessible    = true")],
    "rds_iam_auth": [("database.tf", "  iam_database_authentication_enabled = false", "  iam_database_authentication_enabled = true")],
    "rds_unencrypted": [("database.tf", "  storage_encrypted = true", "  storage_encrypted = false")],
    "audit_versioning_suspended": [
        ("storage.tf", 'resource "aws_s3_bucket_versioning" "audit_log" {\n  bucket = aws_s3_bucket.audit_log.bucket\n\n  versioning_configuration {\n    status = "Enabled"',
         'resource "aws_s3_bucket_versioning" "audit_log" {\n  bucket = aws_s3_bucket.audit_log.bucket\n\n  versioning_configuration {\n    status = "Suspended"')
    ],
    "reports_versioning_enabled": [("storage.tf", None, VERSIONING_REPORTS)],
    "kms_rotation_off": [("kms.tf", "  enable_key_rotation     = true", "  enable_key_rotation     = false")],
    "kms_description": [
        ("kms.tf", '  description             = "CMK for customer data and the core ledger database"',
         '  description             = "CMK for customer data and the core ledger database (PCI)"')
    ],
    "kms_deleted": [
        ("delete", "aws_kms_key", "data", "kms.tf"),
        ("database.tf", "  kms_key_id        = aws_kms_key.data.arn\n", ""),
        ("storage.tf", '      sse_algorithm     = "aws:kms"\n      kms_master_key_id = aws_kms_key.data.arn', '      sse_algorithm     = "AES256"'),
    ],
    # Deleting the key alone leaves dangling references: the plan fails and the HCL fallback is used.
    "kms_deleted_fallback": [("delete", "aws_kms_key", "data", "kms.tf")],
    "delete_two_legacy": [
        ("delete", "aws_s3_bucket", "legacy_exports", "storage.tf"),
        ("delete", "aws_s3_bucket", "legacy_tmp", "storage.tf"),
    ],
    "delete_four_legacy": [
        ("delete", "aws_s3_bucket", "legacy_exports", "storage.tf"),
        ("delete", "aws_s3_bucket", "legacy_tmp", "storage.tf"),
        ("delete", "aws_security_group", "legacy_ftp", "security_groups.tf"),
        ("delete", "aws_subnet", "legacy_batch", "network.tf"),
    ],
    "delete_one_legacy_subnet": [("delete", "aws_subnet", "legacy_batch", "network.tf")],
    "delete_audit_2023": [("delete", "aws_s3_bucket", "audit_log_2023", "storage.tf")],
    "delete_legacy_tmp": [("delete", "aws_s3_bucket", "legacy_tmp", "storage.tf")],
    "rds_identifier_rename": [('database.tf', '  identifier     = "fintech-core-db"', '  identifier     = "fintech-ledger-db"')],
    "rds_tag_rename": [('database.tf', '    Name                = "fintech-core-db"', '    Name                = "fintech-ledger-db"')],
    "rds_instance_class": [("database.tf", '  instance_class = "db.t3.medium"', '  instance_class = "db.t3.large"')],
    "rds_backup_retention": [("database.tf", "  backup_retention_period             = 7", "  backup_retention_period             = 14")],
    "ci_attach_read_policy": [("iam.tf", None, ATTACH_CI)],
    "app_role_session_4h": [
        ("iam.tf", '  name                 = "${local.name_prefix}-app"\n  max_session_duration = 3600',
         '  name                 = "${local.name_prefix}-app"\n  max_session_duration = 14400')
    ],
}


def apply_case(ws: Workspace, edits: list[tuple]) -> None:
    for edit in edits:
        if edit[0] == "delete":
            _, rtype, name, fname = edit
            text = (ws.root / fname).read_text(encoding="utf-8")
            old, new = remove_resource(text, rtype, name)
        else:
            fname, old, new = edit
            if old is None:  # append
                text = (ws.root / fname).read_text(encoding="utf-8")
                old, new = text, text + new
        result = ws.edit_file(fname, old, new)
        if not result.ok:
            raise RuntimeError(f"edit failed in {fname}: {result.message}")


def main() -> int:
    cfg = load_config()
    runner = TerraformRunner(cfg)
    out_dir = ROOT / "policies" / "testdata"
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="cg-fixtures-"))
    try:
        for name, edits in CASES.items():
            ws = Workspace.create(ROOT / cfg.terraform.env_dir, tmp / name, runner)
            apply_case(ws, edits)
            ev = ws.evaluate()
            if ev.changeset.source != "plan" and not name.endswith("_fallback"):
                raise RuntimeError(f"{name}: plan failed: {ev.plan_error}")
            request = ChangeRequest(
                id=f"FIX-{name}", session_id=f"FIX-{name}", requester="bob", approver="alice",
                ticket=Ticket(id="CHG-9000", title=name), timestamp=SAT, text=f"fixture {name}",
            )
            session = SessionState(session_id=request.session_id, window_id="2026-10-17T02:00Z",
                                   window_totals=WindowTotals(window_id="2026-10-17T02:00Z"))
            pi = build_policy_input(action="terraform_apply", args={}, request=request, session=session,
                                    agent_id=cfg.agent.id, workspace=ws, changeset=ev.changeset)
            doc = {name: json.loads(pi.model_dump_json())}
            (out_dir / f"{name}.json").write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
            s = ev.changeset.summary
            print(f"{name:28s} {ev.changeset.source:12s} +{s.create} ~{s.update} -{s.delete}  {[c.address for c in ev.changeset.changes]}", flush=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
