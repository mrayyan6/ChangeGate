# End to end decisions of the whole bundle on every fixture, and the decision precedence.
package changegate.main_test

import rego.v1

import data.changegate.main

summary(d) := [d.decision, {r.rule_id | some r in d.reasons}]

expected := {
	"noop": ["allow", set()],
	"bastion_ssh_world": ["deny", {"SEC-001"}],
	"bastion_ssh_vpn": ["allow", set()],
	"reports_acl_public": ["deny", {"SEC-002"}],
	"reports_acl_private": ["allow", set()],
	"reports_pab_off": ["deny", {"SEC-003"}],
	"customer_sse_deleted": ["deny", {"SEC-004"}],
	"customer_sse_bucket_key": ["allow", set()],
	"iam_wildcard": ["deny", {"SEC-005"}],
	"iam_list_bucket": ["require_approval", {"SOD-001"}],
	"rds_public": ["deny", {"SEC-006"}],
	"rds_iam_auth": ["allow", set()],
	"rds_unencrypted": ["deny", {"SEC-006", "BR-003"}],
	"audit_versioning_suspended": ["deny", {"SEC-007"}],
	"reports_versioning_enabled": ["allow", set()],
	"kms_rotation_off": ["deny", {"SEC-008"}],
	"kms_description": ["allow", set()],
	"kms_deleted": ["deny", {"BR-002", "BR-003", "SEC-004"}],
	"kms_deleted_fallback": ["deny", {"BR-002"}],
	"delete_two_legacy": ["allow", set()],
	"delete_four_legacy": ["deny", {"BR-001", "CUM-001"}],
	"delete_one_legacy_subnet": ["allow", set()],
	"delete_audit_2023": ["deny", {"BR-002"}],
	"delete_legacy_tmp": ["allow", set()],
	"rds_identifier_rename": ["deny", {"BR-003"}],
	"rds_tag_rename": ["allow", set()],
	"rds_instance_class": ["allow", set()],
	"rds_backup_retention": ["allow", set()],
	"ci_attach_read_policy": ["require_approval", {"SOD-001"}],
	"app_role_session_4h": ["require_approval", {"SOD-001"}],
}

test_every_fixture_has_an_expectation if {
	every name, _ in data.testdata {
		expected[name]
	}
}

test_fixture_decisions if {
	every name, want in expected {
		summary(main.decision) == want with input as data.testdata[name]
	}
}

test_deny_wins_over_approval if {
	# IAM wildcard needs approval (SOD-001) and is denied (SEC-005): only the deny is reported.
	summary(main.decision) == ["deny", {"SEC-005"}] with input as data.testdata.iam_wildcard
}

test_window_and_sod_combine if {
	inp := object.union(data.testdata.ci_attach_read_policy, {"clock": {"now": "2026-10-14T15:00:00Z"}})
	summary(main.decision) == ["require_approval", {"SOD-001", "CW-001"}] with input as inp
}

test_unplannable_change_is_denied if {
	inp := object.union(data.testdata.noop, {"changeset": {"changes": [], "errors": ["plan failed"]}})
	summary(main.decision) == ["deny", {"CS-001"}] with input as inp
}

test_read_only_actions_allowed if {
	summary(main.decision) == ["allow", set()] with input as object.union(data.testdata.bastion_ssh_world, {"action": "terraform_plan"})
	summary(main.decision) == ["allow", set()] with input as object.union(data.testdata.delete_four_legacy, {"action": "request_approval"})
}

incomplete contains [name, r.rule_id] if {
	some name, _ in expected
	reasons := main.decision.reasons with input as data.testdata[name]
	some r in reasons
	not complete(r)
}

complete(r) if {
	r.rule_id != ""
	r.message != ""
	r.hint != ""
	r.effect in {"deny", "require_approval"}
}

test_every_reason_is_complete if {
	count(incomplete) == 0
}
