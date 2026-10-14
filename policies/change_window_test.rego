package changegate.change_window_test

import rego.v1

import data.changegate.change_window

ids(rs) := {r.rule_id | some r in rs}

at(case, now) := object.union(case, {"clock": {"now": now}})

approved(case) := object.union(case, {"session": {"approvals": [{
	"approval_id": "APR-1", "request_id": "r", "ticket_id": "CHG-9000", "requester": "bob", "approver": "alice",
	"granted": true, "reason": "emergency", "detail": "", "changeset_digest": case.changeset.digest,
	"timestamp": "2026-10-14T15:00:00Z",
}]}})

test_outside_window_needs_approval if {
	ids(change_window.require_approval) == {"CW-001"} with input as at(data.testdata.rds_instance_class, "2026-10-14T15:00:00Z")
	ids(change_window.require_approval) == {"CW-001"} with input as at(data.testdata.rds_backup_retention, "2026-10-17T04:10:00Z")
}

test_inside_window if {
	count(change_window.require_approval) == 0 with input as data.testdata.rds_instance_class
}

test_boundaries if {
	ids(change_window.require_approval) == {"CW-001"} with input as at(data.testdata.rds_instance_class, "2026-10-17T01:59:00Z")
	count(change_window.require_approval) == 0 with input as at(data.testdata.rds_instance_class, "2026-10-17T02:00:00Z")
	count(change_window.require_approval) == 0 with input as at(data.testdata.rds_instance_class, "2026-10-17T03:59:00Z")
	ids(change_window.require_approval) == {"CW-001"} with input as at(data.testdata.rds_instance_class, "2026-10-17T04:00:00Z")
	ids(change_window.require_approval) == {"CW-001"} with input as at(data.testdata.rds_instance_class, "2026-10-18T02:30:00Z")
}

test_offset_timestamps_are_converted if {
	# 07:30 at +05:00 is 02:30 UTC on Saturday
	count(change_window.require_approval) == 0 with input as at(data.testdata.rds_instance_class, "2026-10-17T07:30:00+05:00")
}

test_valid_emergency_approval if {
	count(change_window.require_approval) == 0 with input as approved(at(data.testdata.rds_instance_class, "2026-10-14T15:00:00Z"))
}

test_no_changes_no_approval if {
	count(change_window.require_approval) == 0 with input as at(data.testdata.noop, "2026-10-14T15:00:00Z")
}

test_not_for_plan if {
	count(change_window.require_approval) == 0 with input as object.union(at(data.testdata.rds_instance_class, "2026-10-14T15:00:00Z"), {"action": "terraform_plan"})
}
