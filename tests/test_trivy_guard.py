import shutil
from types import SimpleNamespace

import pytest

from baselines.trivy_guard import TrivyGuard
from changegate.config import REPO_ROOT, load_config
from changegate.contracts import PolicyInput
from changegate.terraform import TerraformRunner
from changegate.workspace import Workspace

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(not (shutil.which("trivy") and shutil.which("terraform")), reason="trivy or terraform missing"),
]

SSH_OLD = '  egress {\n    description = "Administration traffic into the VPC"'


def _ssh(cidr: str) -> str:
    return (
        f'  ingress {{\n    description = "ssh"\n    from_port   = 22\n    to_port     = 22\n    protocol    = "tcp"\n'
        f'    cidr_blocks = ["{cidr}"]\n  }}\n\n' + SSH_OLD
    )


def _input(action: str) -> PolicyInput:
    return PolicyInput.model_validate(
        {
            "action": action,
            "request": {"id": "r", "session_id": "s", "requester": "bob", "ticket": {"id": "CHG-1"},
                        "timestamp": "2026-10-17T02:30:00Z", "text": "t"},
            "session": {"session_id": "s", "window_id": "w", "window_totals": {"window_id": "w"}},
            "clock": {"now": "2026-10-17T02:30:00Z"},
        }
    )


@pytest.fixture()
def ws(tmp_path):
    cfg = load_config()
    return Workspace.create(REPO_ROOT / cfg.terraform.env_dir, tmp_path / "w", TerraformRunner(cfg))


def test_trivy_denies_new_public_ssh_and_ignores_baseline(ws):
    guard = TrivyGuard(load_config())
    ctx = SimpleNamespace(workspace=ws)
    assert guard.decide(_input("terraform_apply"), ctx).decision == "allow"  # existing findings are not new
    assert ws.edit_file("security_groups.tf", SSH_OLD, _ssh("0.0.0.0/0")).ok
    decision = guard.decide(_input("terraform_apply"), ctx)
    assert decision.decision == "deny"
    assert any(r.resource == "aws_security_group.bastion" for r in decision.reasons)
    assert all(r.rule_id.startswith("TRIVY-") and r.hint for r in decision.reasons)
    assert guard.decide(_input("terraform_plan"), ctx).decision == "allow"


def test_trivy_allows_vpn_ssh(ws):
    guard = TrivyGuard(load_config())
    assert ws.edit_file("security_groups.tf", SSH_OLD, _ssh("10.50.0.0/16")).ok
    assert guard.decide(_input("terraform_apply"), SimpleNamespace(workspace=ws)).decision == "allow"
