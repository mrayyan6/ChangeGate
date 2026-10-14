package changegate.sod_approval_test

import rego.v1

import data.changegate.sod_approval

ids(rs) := {r.rule_id | some r in rs}

approval(approver, granted, digest) := {
	"approval_id": "APR-1", "request_id": "r", "ticket_id": "CHG-9000", "requester": "bob", "approver": approver,
	"granted": granted, "reason": "needed", "detail": "", "changeset_digest": digest, "timestamp": "2026-10-17T02:30:00Z",
}

with_approvals(case, list) := object.union(case, {"session": {"approvals": list}})

test_privileged_fixtures_need_approval if {
	ids(sod_approval.require_approval) == {"SOD-001"} with input as data.testdata.iam_list_bucket
	ids(sod_approval.require_approval) == {"SOD-001"} with input as data.testdata.ci_attach_read_policy
	ids(sod_approval.require_approval) == {"SOD-001"} with input as data.testdata.app_role_session_4h
}

test_other_fixtures_do_not if {
	count(sod_approval.require_approval) == 0 with input as data.testdata.rds_instance_class
	count(sod_approval.require_approval) == 0 with input as data.testdata.kms_description
	count(sod_approval.require_approval) == 0 with input as data.testdata.delete_two_legacy
}

test_valid_approval_clears if {
	case := data.testdata.ci_attach_read_policy
	inp := with_approvals(case, [approval("alice", true, case.changeset.digest)])
	count(sod_approval.require_approval) == 0 with input as inp
	count(sod_approval.deny) == 0 with input as inp
}

test_approval_for_other_change_does_not_count if {
	case := data.testdata.ci_attach_read_policy
	ids(sod_approval.require_approval) == {"SOD-001"} with input as with_approvals(case, [approval("alice", true, "other-digest")])
}

test_rejected_approval_does_not_count if {
	case := data.testdata.ci_attach_read_policy
	ids(sod_approval.require_approval) == {"SOD-001"} with input as with_approvals(case, [approval("alice", false, case.changeset.digest)])
}

test_self_approval_denied if {
	case := data.testdata.ci_attach_read_policy
	ids(sod_approval.deny) == {"SOD-002"} with input as with_approvals(case, [approval("bob", true, case.changeset.digest)])
}

test_agent_approval_denied if {
	case := data.testdata.ci_attach_read_policy
	ids(sod_approval.deny) == {"SOD-003"} with input as with_approvals(case, [approval("changegate-agent", true, case.changeset.digest)])
}

test_one_valid_among_bad_approvals_wins if {
	case := data.testdata.ci_attach_read_policy
	inp := with_approvals(case, [
		approval("bob", true, case.changeset.digest),
		approval("alice", true, case.changeset.digest),
	])
	count(sod_approval.deny) == 0 with input as inp
	count(sod_approval.require_approval) == 0 with input as inp
}

test_kms_key_policy_change_needs_approval if {
	c := {"address": "aws_kms_key.data", "type": "aws_kms_key", "name": "data", "action": "update", "changed_attributes": ["policy"], "before": {}, "after": {}, "unknown_after": [], "references": {}}
	ids(sod_approval.require_approval) == {"SOD-001"} with input as object.union(data.testdata.noop, {"changeset": {"changes": [c]}})
}

test_not_for_plan if {
	count(sod_approval.require_approval) == 0 with input as object.union(data.testdata.iam_list_bucket, {"action": "terraform_plan"})
}
