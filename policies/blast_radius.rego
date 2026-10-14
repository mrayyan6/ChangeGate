# Blast radius of one pending terraform_apply: how much a single change may delete, destroy or touch.
# Limits and tag conventions come from data.changegate.params (policies/data.json).
package changegate.blast_radius

import rego.v1

import data.changegate.lib

# BR-001: too many deletes in one change.
deny contains reason("BR-001", null, msg, hint) if {
	lib.is_apply
	limit := lib.params.max_deletes_per_change
	lib.n_deletes > limit
	msg := sprintf("This apply would delete %s (%s), more than the limit of %d per change.", [
		counted(lib.n_deletes, "resource"),
		address_list(addresses(lib.deletes)),
		limit,
	])
	hint := sprintf(
		"Delete at most %d resources in this change: keep the others in the configuration and defer their deletion to the next change window.",
		[limit],
	)
}

# BR-002: deleting a resource tagged critical, or one still under retention.
deny contains reason("BR-002", c.address, msg, hint) if {
	lib.is_apply
	some c in lib.deletes
	why := protections(lib.tags_of(c.before))
	count(why) > 0
	msg := sprintf("%s is %s, so automation may not delete it.", [c.address, join_words(why)])
	hint := sprintf(
		"Keep %s in the configuration so this change does not delete it. Automation may not delete critical or retained resources, so raise a decommission ticket with the data owner instead.",
		[c.address],
	)
}

# BR-003: an update that Terraform can only carry out by replacing a stateful resource.
deny contains reason("BR-003", c.address, msg, hint) if {
	lib.is_apply
	some c in lib.changes
	c.action == "update"
	c.type in lib.params.stateful_types
	attrs := force_new_changes(c)
	count(attrs) > 0
	names := join_words(attrs)
	msg := sprintf(
		"Changing %s on %s forces Terraform to replace this %s, destroying the existing resource and its data.",
		[names, c.address, c.type],
	)
	hint := sprintf(
		"Revert %s and make a change that updates in place instead (for example a tag), or plan a data migration with the data owner if a new resource is really needed.",
		[names],
	)
}

# BR-004: too many resources touched by one change.
deny contains reason("BR-004", null, msg, hint) if {
	lib.is_apply
	limit := lib.params.max_changes_per_change
	lib.n_changes > limit
	msg := sprintf("This apply would change %s (%s), more than the limit of %d per change.", [
		counted(lib.n_changes, "resource"),
		address_list(addresses(lib.changes)),
		limit,
	])
	hint := sprintf(
		"Split the work so that this change touches at most %d resources, and apply the rest in the next change window.",
		[limit],
	)
}

# Why a resource with these tags may not be deleted, as phrases for a message. Empty when it may go.
protections(tags) := array.concat(critical_phrases(tags), retention_phrases(tags))

critical_phrases(tags) := [sprintf("marked critical (%s = %s)", [key, value])] if {
	key := lib.params.critical_tag.key
	value := tags[key]
	value in lib.params.critical_tag.values
} else := []

# A YYYY-MM-DD retention date protects the resource through that day (UTC). Without a clock it stays protected.
retention_phrases(tags) := [sprintf("under retention until %s (%s tag)", [value, key])] if {
	key := lib.params.retention_tag
	value := tags[key]
	is_string(value)
	regex.match(`^\d{4}-\d{2}-\d{2}$`, value)
	not expired(value)
} else := []

expired(date) if date < lib.today

# Changed attributes that make Terraform replace a resource of this type. Attributes that are only
# unknown after apply (unknown_after) are not changes.
force_new_changes(c) := sort({a |
	some a in c.changed_attributes
	a in object.get(lib.params.force_new_attributes, c.type, [])
})

addresses(cs) := sort({c.address | some c in cs})

reason(rule_id, resource, message, hint) := {
	"rule_id": rule_id,
	"policy": "blast_radius",
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
