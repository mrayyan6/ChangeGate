package changegate.cumulative_test

import rego.v1

import data.changegate.cumulative

ids(rs) := {r.rule_id | some r in rs}

with_totals(case, deletes, changes) := object.union(case, {"session": {"window_totals": {"deletes": deletes, "changes": changes}}})

test_four_deletes_at_once if {
	ids(cumulative.deny) == {"CUM-001"} with input as data.testdata.delete_four_legacy
}

test_split_deletes_add_up if {
	# two deletes earlier in the window plus one now is three: allowed
	count(cumulative.deny) == 0 with input as with_totals(data.testdata.delete_one_legacy_subnet, 2, 2)

	# three earlier plus one now is four: denied
	ids(cumulative.deny) == {"CUM-001"} with input as with_totals(data.testdata.delete_one_legacy_subnet, 3, 3)
	count(cumulative.deny) == 0 with input as data.testdata.delete_one_legacy_subnet
}

test_no_deletes_do_not_trip_the_delete_budget if {
	count(cumulative.deny) == 0 with input as with_totals(data.testdata.rds_tag_rename, 3, 3)
}

test_change_budget if {
	count(cumulative.deny) == 0 with input as with_totals(data.testdata.rds_tag_rename, 0, 9)
	ids(cumulative.deny) == {"CUM-002"} with input as with_totals(data.testdata.rds_tag_rename, 0, 10)
}

test_message_mentions_window if {
	some r in cumulative.deny with input as with_totals(data.testdata.delete_one_legacy_subnet, 3, 3)
	contains(r.message, "2026-10-17T02:00Z")
}

test_not_for_plan if {
	count(cumulative.deny) == 0 with input as object.union(data.testdata.delete_four_legacy, {"action": "terraform_plan"})
}
