# Change window budgets across requests, which catch a risky change split over several applies.
# input.session.window_totals holds what earlier applies in the current change window already did
# (the pending change is not included). Limits come from data.changegate.params (policies/data.json).
package changegate.cumulative

import rego.v1

import data.changegate.lib

# CUM-001: this change's deletes would push the window past its delete budget.
deny contains reason("CUM-001", null, msg, hint) if {
	lib.is_apply
	lib.n_deletes > 0
	prior := window_total("deletes")
	limit := lib.params.max_deletes_per_window
	prior + lib.n_deletes > limit
	msg := sprintf(
		"This apply would delete %s (%s) after %s in change window %s, bringing the window to %d deletes, over the limit of %d per window.",
		[
			counted(lib.n_deletes, "resource"),
			address_list(addresses(lib.deletes)),
			counted(prior, "earlier delete"),
			window_id,
			prior + lib.n_deletes,
			limit,
		],
	)
	hint := delete_hint(limit - prior)
}

# CUM-002: this change would push the window past its budget of resource changes.
deny contains reason("CUM-002", null, msg, hint) if {
	lib.is_apply
	lib.n_changes > 0
	prior := window_total("changes")
	limit := lib.params.max_changes_per_window
	prior + lib.n_changes > limit
	msg := sprintf(
		"This apply would change %s (%s) after %s in change window %s, bringing the window to %d resource changes, over the limit of %d per window.",
		[
			counted(lib.n_changes, "resource"),
			address_list(addresses(lib.changes)),
			counted(prior, "earlier resource change"),
			window_id,
			prior + lib.n_changes,
			limit,
		],
	)
	hint := change_hint(limit - prior)
}

# Totals of the earlier applies in this window. Missing totals count as zero, so the pending change
# is still held to the window limits on its own.
window_total(field) := object.get(input, ["session", "window_totals", field], 0)

window_id := object.get(input, ["session", "window_id"], "unknown")

# Remediation that says how much of the window budget is left.
delete_hint(room) := "No deletes are left in this change window: keep these resources in the configuration and defer their deletion to the next change window." if {
	room <= 0
} else := sprintf(
	"Delete at most %s in this change window: keep the others in the configuration and defer the remaining deletions to the next change window.",
	[counted(room, "more resource")],
)

change_hint(room) := "No resource changes are left in this change window: defer this change to the next change window." if {
	room <= 0
} else := sprintf(
	"Change at most %s in this change window: split the work and apply the rest in the next change window.",
	[counted(room, "more resource")],
)

addresses(cs) := sort({c.address | some c in cs})

reason(rule_id, resource, message, hint) := {
	"rule_id": rule_id,
	"policy": "cumulative",
	"effect": "deny",
	"severity": "high",
	"resource": resource,
	"message": message,
	"hint": hint,
}

# "1 resource", "4 resources".
counted(n, noun) := sprintf("%d %s", [n, noun]) if {
	n == 1
} else := sprintf("%d %ss", [n, noun])

# "a", "a and b", "a, b and c".
join_words(items) := items[0] if {
	count(items) == 1
} else := sprintf("%s and %s", [concat(", ", array.slice(items, 0, count(items) - 1)), items[count(items) - 1]])

# Up to five addresses, then how many more.
address_list(addrs) := join_words(addrs) if {
	count(addrs) <= 5
} else := sprintf("%s and %d more", [concat(", ", array.slice(addrs, 0, 5)), count(addrs) - 5])
