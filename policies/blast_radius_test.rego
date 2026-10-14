package changegate.blast_radius_test

import rego.v1

import data.changegate.blast_radius

ids(rs) := {r.rule_id | some r in rs}

with_changes(cs) := object.union(data.testdata.noop, {"changeset": {"changes": cs}})

deleted(addr, tags) := {"address": addr, "type": "aws_s3_bucket", "name": "x", "action": "delete", "changed_attributes": [], "before": {"tags": tags}, "after": null, "unknown_after": [], "references": {}}

updated(addr, n) := {"address": sprintf("%s%d", [addr, n]), "type": "aws_s3_bucket", "name": "x", "action": "update", "changed_attributes": ["tags"], "before": {}, "after": {}, "unknown_after": [], "references": {}}

test_fixtures if {
	ids(blast_radius.deny) == {"BR-001"} with input as data.testdata.delete_four_legacy
	ids(blast_radius.deny) == {"BR-002"} with input as data.testdata.delete_audit_2023
	ids(blast_radius.deny) == {"BR-002", "BR-003"} with input as data.testdata.kms_deleted
	ids(blast_radius.deny) == {"BR-002"} with input as data.testdata.kms_deleted_fallback
	ids(blast_radius.deny) == {"BR-003"} with input as data.testdata.rds_identifier_rename
	ids(blast_radius.deny) == {"BR-003"} with input as data.testdata.rds_unencrypted
}

test_safe_fixtures if {
	count(blast_radius.deny) == 0 with input as data.testdata.delete_two_legacy
	count(blast_radius.deny) == 0 with input as data.testdata.delete_legacy_tmp
	count(blast_radius.deny) == 0 with input as data.testdata.rds_tag_rename
	count(blast_radius.deny) == 0 with input as data.testdata.rds_backup_retention
	count(blast_radius.deny) == 0 with input as data.testdata.delete_one_legacy_subnet
}

test_delete_limit_boundary if {
	three := [deleted("a.1", {}), deleted("a.2", {}), deleted("a.3", {})]
	count(blast_radius.deny) == 0 with input as with_changes(three)
	ids(blast_radius.deny) == {"BR-001"} with input as with_changes(array.concat(three, [deleted("a.4", {})]))
}

test_retention_dates if {
	# fixtures run on 2026-10-17
	ids(blast_radius.deny) == {"BR-002"} with input as with_changes([deleted("a.r", {"retention_until": "2026-10-17"})])
	count(blast_radius.deny) == 0 with input as with_changes([deleted("a.r", {"retention_until": "2026-10-16"})])
	count(blast_radius.deny) == 0 with input as with_changes([deleted("a.r", {"retention_until": "someday"})])
	ids(blast_radius.deny) == {"BR-002"} with input as with_changes([deleted("a.c", {"criticality": "high"})])
	count(blast_radius.deny) == 0 with input as with_changes([deleted("a.c", {"criticality": "low"})])
}

test_change_limit if {
	ten := [updated("a.u", n) | some n in numbers.range(1, 10)]
	count(blast_radius.deny) == 0 with input as with_changes(ten)
	ids(blast_radius.deny) == {"BR-004"} with input as with_changes(array.concat(ten, [updated("a.u", 11)]))
}

test_not_for_plan if {
	count(blast_radius.deny) == 0 with input as object.union(data.testdata.delete_four_legacy, {"action": "terraform_plan"})
}
