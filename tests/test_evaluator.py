import json

from changegate.contracts import Assertion
from changegate.evaluator import all_passed, evaluate_assertion, evaluate_assertions, flatten, resolve_path


def _res(rtype, values, refs=None, unknown=None):
    return {"type": rtype, "name": "x", "values": values, "references": refs or {}, "unknown": unknown or []}


POLICY = json.dumps({"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}})

INITIAL = {
    "aws_s3_bucket.audit_log": _res("aws_s3_bucket", {"bucket": "audit"}),
    "aws_s3_bucket.audit_log_2023": _res("aws_s3_bucket", {"bucket": "audit-2023"}),
    "aws_s3_bucket.legacy_tmp": _res("aws_s3_bucket", {"bucket": "tmp"}),
    "aws_s3_bucket.legacy_exports": _res("aws_s3_bucket", {"bucket": "exports"}),
    "aws_iam_policy.app": _res("aws_iam_policy", {"policy": POLICY}),
    "aws_db_instance.main": _res("aws_db_instance", {"instance_class": "db.t3.medium", "publicly_accessible": False}),
    "aws_security_group.bastion": _res(
        "aws_security_group",
        {"ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["10.50.0.0/16"], "ipv6_cidr_blocks": []}]},
    ),
    "aws_security_group.alb": _res(
        "aws_security_group",
        {"ingress": [{"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": []}]},
    ),
}


def check(final, **kw):
    return evaluate_assertion(Assertion(**kw), final, INITIAL)


def test_resolve_path_basics_and_json_strings():
    values = {"a": [{"b": 1}, {"b": 2}], "policy": POLICY}
    assert resolve_path(values, "a.*.b") == [1, 2]
    assert resolve_path(values, "a.1.b") == [2]
    assert resolve_path(values, "a.5.b") == []
    assert resolve_path(values, "policy.Statement.*.Action") == ["s3:GetObject"]  # object Statement wrapped
    assert resolve_path(values, "missing.path") == []
    assert flatten([1, [2, [3]], []]) == [1, 2, 3]


def test_exists_absent():
    assert check(INITIAL, type="resource_exists", address="aws_db_instance.main").passed
    assert not check(INITIAL, type="resource_absent", address="aws_db_instance.main").passed
    final = {k: v for k, v in INITIAL.items() if k != "aws_s3_bucket.legacy_tmp"}
    assert check(final, type="resource_absent", address="aws_s3_bucket.legacy_tmp").passed


def test_attr_equals_contains_not_contains():
    assert check(INITIAL, type="attr_equals", address="aws_db_instance.main", path="instance_class", value="db.t3.medium").passed
    assert not check(INITIAL, type="attr_equals", address="aws_db_instance.main", path="publicly_accessible", value=0).passed
    assert not check(INITIAL, type="attr_equals", address="aws_db_instance.main", path="nope", value=1).passed
    assert check(INITIAL, type="attr_contains", address="aws_security_group.bastion", path="ingress.*.cidr_blocks", value="10.50.0.0/16").passed
    assert not check(INITIAL, type="attr_contains", address="aws_security_group.bastion", path="ingress.*.cidr_blocks", value="0.0.0.0/0").passed
    assert check(INITIAL, type="attr_not_contains", address="aws_iam_policy.app", path="policy.Statement.*.Action", value="*").passed
    wildcard = dict(INITIAL)
    wildcard["aws_iam_policy.app"] = _res("aws_iam_policy", {"policy": json.dumps({"Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": "*"}]})})
    assert not check(wildcard, type="attr_not_contains", address="aws_iam_policy.app", path="policy.Statement.*.Action", value="*").passed
    # an absent resource cannot contain anything
    assert check({}, type="attr_not_contains", address="aws_iam_policy.app", path="policy", value="*").passed


def test_no_delete_of_and_max_absent():
    final = {k: v for k, v in INITIAL.items() if k not in ("aws_s3_bucket.legacy_tmp", "aws_s3_bucket.legacy_exports")}
    assert check(final, type="no_delete_of", addresses=["aws_s3_bucket.audit_log*", "aws_db_instance.main"]).passed
    assert not check(final, type="no_delete_of", address="aws_s3_bucket.legacy_*").passed
    legacy = ["aws_s3_bucket.legacy_tmp", "aws_s3_bucket.legacy_exports"]
    assert check(final, type="max_absent", addresses=legacy, max=2).passed
    assert not check(final, type="max_absent", addresses=legacy, max=1).passed


def test_sg_ingress_inline_standalone_and_any():
    assert check(INITIAL, type="sg_ingress", sg="aws_security_group.bastion", port=22, cidr="10.50.0.0/16", present=True).passed
    assert check(INITIAL, type="sg_ingress", sg="*", port=22, cidr="0.0.0.0/0", present=False).passed
    # the public 443 rule on the ALB does not count as SSH
    assert check(INITIAL, type="sg_ingress", sg="*", port=443, cidr="0.0.0.0/0", present=True).passed
    world = dict(INITIAL)
    world["aws_vpc_security_group_ingress_rule.ssh"] = _res(
        "aws_vpc_security_group_ingress_rule",
        {"cidr_ipv4": "0.0.0.0/0", "from_port": 22, "to_port": 22, "ip_protocol": "tcp"},
        refs={"security_group_id": ["aws_security_group.bastion"]},
    )
    assert not check(world, type="sg_ingress", sg="*", port=22, cidr="0.0.0.0/0", present=False).passed
    assert check(world, type="sg_ingress", sg="aws_security_group.bastion", port=22, cidr="0.0.0.0/0", present=True).passed
    all_ports = dict(INITIAL)
    all_ports["aws_security_group_rule.any"] = _res(
        "aws_security_group_rule",
        {"type": "ingress", "protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]},
        refs={"security_group_id": ["aws_security_group.alb"]},
    )
    assert not check(all_ports, type="sg_ingress", sg="*", port=22, cidr="0.0.0.0/0", present=False).passed


def test_resource_matches_is_name_independent():
    final = dict(INITIAL)
    final["aws_iam_role_policy_attachment.anything"] = _res("aws_iam_role_policy_attachment", {"role": "fintech-prod-ci-deploy"})
    q = dict(type="resource_matches", address="aws_iam_role_policy_attachment.*", path="role", value="fintech-prod-ci-deploy")
    assert check(final, present=True, **q).passed
    assert not check(final, present=False, **q).passed
    assert check(INITIAL, present=False, **q).passed
    assert not check(INITIAL, type="resource_matches", address="aws_iam_role.*", path="name", value="x").passed  # needs present


def test_invalid_assertions_fail_and_all_passed():
    result = evaluate_assertion(Assertion(type="attr_equals", address="aws_db_instance.main"), INITIAL, INITIAL)
    assert not result.passed and "path" in result.detail
    results = evaluate_assertions([Assertion(type="resource_exists", address="aws_db_instance.main")], INITIAL, INITIAL)
    assert all_passed(results) and all_passed([])
