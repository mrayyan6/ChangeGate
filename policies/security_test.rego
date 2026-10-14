package changegate.security_test

import rego.v1

import data.changegate.security

ids(rs) := {r.rule_id | some r in rs}

with_changes(cs) := object.union(data.testdata.noop, {"changeset": {"changes": cs}})

change(rtype, action, before, after) := {
	"address": sprintf("%s.t", [rtype]),
	"type": rtype,
	"name": "t",
	"action": action,
	"changed_attributes": [],
	"before": before,
	"after": after,
	"unknown_after": [],
	"references": {},
}

sg(ingress) := {"ingress": ingress, "name": "x"}

rule(cidr, from, to, proto) := {"cidr_blocks": [cidr], "ipv6_cidr_blocks": [], "from_port": from, "to_port": to, "protocol": proto}

# Fixtures: the unsafe twin is denied with the expected rule, the safe twin is not.

test_fixture_denies if {
	ids(security.deny) == {"SEC-001"} with input as data.testdata.bastion_ssh_world
	ids(security.deny) == {"SEC-002"} with input as data.testdata.reports_acl_public
	ids(security.deny) == {"SEC-003"} with input as data.testdata.reports_pab_off
	ids(security.deny) == {"SEC-004"} with input as data.testdata.customer_sse_deleted
	ids(security.deny) == {"SEC-005"} with input as data.testdata.iam_wildcard
	ids(security.deny) == {"SEC-006"} with input as data.testdata.rds_public
	ids(security.deny) == {"SEC-006"} with input as data.testdata.rds_unencrypted
	ids(security.deny) == {"SEC-007"} with input as data.testdata.audit_versioning_suspended
	ids(security.deny) == {"SEC-008"} with input as data.testdata.kms_rotation_off
	ids(security.deny) == {"SEC-004"} with input as data.testdata.kms_deleted
}

test_fixture_safe_twins if {
	count(security.deny) == 0 with input as data.testdata.bastion_ssh_vpn
	count(security.deny) == 0 with input as data.testdata.reports_acl_private
	count(security.deny) == 0 with input as data.testdata.customer_sse_bucket_key
	count(security.deny) == 0 with input as data.testdata.iam_list_bucket
	count(security.deny) == 0 with input as data.testdata.rds_iam_auth
	count(security.deny) == 0 with input as data.testdata.reports_versioning_enabled
	count(security.deny) == 0 with input as data.testdata.kms_description
	count(security.deny) == 0 with input as data.testdata.rds_tag_rename
	count(security.deny) == 0 with input as data.testdata.noop
}

test_not_for_plan if {
	count(security.deny) == 0 with input as object.union(data.testdata.bastion_ssh_world, {"action": "terraform_plan"})
}

test_message_names_resource_and_hint_names_vpn if {
	some r in security.deny with input as data.testdata.bastion_ssh_world
	contains(r.message, "aws_security_group.bastion")
	contains(r.hint, "10.50.0.0/16")
}

# SEC-001 bypass variants.

test_ipv6_world_is_public if {
	ipv6 := {"cidr_blocks": [], "ipv6_cidr_blocks": ["::/0"], "from_port": 22, "to_port": 22, "protocol": "tcp"}
	ids(security.deny) == {"SEC-001"} with input as with_changes([change("aws_security_group", "create", null, sg([ipv6]))])
}

test_all_ports_and_protocol_minus_one if {
	ids(security.deny) == {"SEC-001"} with input as with_changes([change("aws_security_group", "create", null, sg([rule("0.0.0.0/0", 0, 65535, "tcp")]))])
	ids(security.deny) == {"SEC-001"} with input as with_changes([change("aws_security_group", "create", null, sg([rule("0.0.0.0/0", 0, 0, "-1")]))])
}

test_range_spanning_allowed_ports_is_denied if {
	ids(security.deny) == {"SEC-001"} with input as with_changes([change("aws_security_group", "create", null, sg([rule("0.0.0.0/0", 80, 443, "tcp")]))])
}

test_public_https_is_allowed if {
	count(security.deny) == 0 with input as with_changes([change("aws_security_group", "create", null, sg([rule("0.0.0.0/0", 443, 443, "tcp")]))])
}

test_existing_public_rule_is_not_new if {
	before := sg([rule("0.0.0.0/0", 8080, 8080, "tcp")])
	after := object.union(before, {"description": "changed"})
	count(security.deny) == 0 with input as with_changes([change("aws_security_group", "update", before, after)])
}

test_standalone_rule_resources if {
	vpc_rule := {"cidr_ipv4": "0.0.0.0/0", "from_port": 3389, "to_port": 3389, "ip_protocol": "tcp"}
	ids(security.deny) == {"SEC-001"} with input as with_changes([change("aws_vpc_security_group_ingress_rule", "create", null, vpc_rule)])
	all_traffic := {"cidr_ipv4": "0.0.0.0/0", "ip_protocol": "-1"}
	ids(security.deny) == {"SEC-001"} with input as with_changes([change("aws_vpc_security_group_ingress_rule", "create", null, all_traffic)])
	old_style := object.union(rule("0.0.0.0/0", 22, 22, "tcp"), {"type": "ingress"})
	ids(security.deny) == {"SEC-001"} with input as with_changes([change("aws_security_group_rule", "create", null, old_style)])
	egress := object.union(rule("0.0.0.0/0", 22, 22, "tcp"), {"type": "egress"})
	count(security.deny) == 0 with input as with_changes([change("aws_security_group_rule", "create", null, egress)])
}

# SEC-002 variants.

bucket_policy(principal) := {"policy": json.marshal({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": principal, "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]})}

test_bucket_policy_principals if {
	ids(security.deny) == {"SEC-002"} with input as with_changes([change("aws_s3_bucket_policy", "create", null, bucket_policy("*"))])
	ids(security.deny) == {"SEC-002"} with input as with_changes([change("aws_s3_bucket_policy", "create", null, bucket_policy({"AWS": ["*"]}))])
	count(security.deny) == 0 with input as with_changes([change("aws_s3_bucket_policy", "create", null, bucket_policy({"AWS": "arn:aws:iam::222222222222:root"}))])
}

test_acl_grant_to_all_users if {
	acp := {"access_control_policy": [{"grant": [{"grantee": [{"type": "Group", "uri": "http://acs.amazonaws.com/groups/global/AllUsers"}], "permission": "READ"}]}]}
	ids(security.deny) == {"SEC-002"} with input as with_changes([change("aws_s3_bucket_acl", "create", null, acp)])
}

# SEC-003 and SEC-004 variants.

test_public_access_block_deleted if {
	ids(security.deny) == {"SEC-003"} with input as with_changes([change("aws_s3_bucket_public_access_block", "delete", {"bucket": "b"}, null)])
}

sse(alg) := {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": alg}]}]}

test_encryption_algorithms if {
	count(security.deny) == 0 with input as with_changes([change("aws_s3_bucket_server_side_encryption_configuration", "create", null, sse("AES256"))])
	count(security.deny) == 0 with input as with_changes([change("aws_s3_bucket_server_side_encryption_configuration", "update", sse("aws:kms"), sse("aws:kms:dsse"))])
	ids(security.deny) == {"SEC-004"} with input as with_changes([change("aws_s3_bucket_server_side_encryption_configuration", "update", sse("aws:kms"), sse("AES256"))])
	ids(security.deny) == {"SEC-004"} with input as with_changes([change("aws_s3_bucket_server_side_encryption_configuration", "create", null, sse("none"))])
	ids(security.deny) == {"SEC-004"} with input as with_changes([change("aws_ebs_volume", "create", null, {"encrypted": false})])
}

# SEC-005 variants.

iam(statement) := {"policy": json.marshal({"Version": "2012-10-17", "Statement": statement})}

test_iam_wildcards if {
	ids(security.deny) == {"SEC-005"} with input as with_changes([change("aws_iam_policy", "update", {}, iam({"Effect": "Allow", "Action": "s3:*", "Resource": "*"}))])
	ids(security.deny) == {"SEC-005"} with input as with_changes([change("aws_iam_role_policy", "create", null, iam([{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]))])
	count(security.deny) == 0 with input as with_changes([change("aws_iam_policy", "update", {}, iam([{"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::b/*"}]))])
	count(security.deny) == 0 with input as with_changes([change("aws_iam_policy", "update", {}, iam([{"Effect": "Deny", "Action": "*", "Resource": "*"}]))])
}

test_admin_attachment_and_open_trust if {
	ids(security.deny) == {"SEC-005"} with input as with_changes([change("aws_iam_role_policy_attachment", "create", null, {"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"})])
	trust := {"assume_role_policy": json.marshal({"Statement": {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}})}
	ids(security.deny) == {"SEC-005"} with input as with_changes([change("aws_iam_role", "update", {}, trust)])
}

# SEC-007 variants.

versioning(bucket, status) := {"bucket": bucket, "versioning_configuration": [{"status": status}]}

test_versioning_only_matters_for_audit_buckets if {
	count(security.deny) == 0 with input as with_changes([change("aws_s3_bucket_versioning", "update", versioning("fintech-prod-reports", "Enabled"), versioning("fintech-prod-reports", "Suspended"))])
	ids(security.deny) == {"SEC-007"} with input as with_changes([change("aws_s3_bucket_versioning", "delete", versioning("fintech-prod-audit-log", "Enabled"), null)])
}

test_audit_bucket_found_through_references if {
	c := object.union(change("aws_s3_bucket_versioning", "update", versioning("unknown", "Enabled"), {"versioning_configuration": [{"status": "Disabled"}]}), {"references": {"bucket": ["aws_s3_bucket.audit_log"]}})
	ids(security.deny) == {"SEC-007"} with input as with_changes([c])
}
