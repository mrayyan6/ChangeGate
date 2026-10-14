# Shared helpers for the ChangeGate policies. No decisions are made here.
package changegate.lib

import rego.v1

params := data.changegate.params

is_apply if input.action == "terraform_apply"

# Resource changes of the pending apply. Empty for every other action.
changes contains c if {
	is_apply
	some c in input.changeset.changes
}

writes contains c if {
	some c in changes
	c.action in {"create", "update"}
}

deletes contains c if {
	some c in changes
	c.action == "delete"
}

n_changes := count(changes)

n_deletes := count(deletes)

# Tags of a values object, or an empty object.
tags_of(values) := t if {
	t := values.tags
	is_object(t)
} else := {}

# Parse a JSON document that may arrive as a string (IAM policies) or as an object.
json_doc(raw) := doc if {
	is_string(raw)
	doc := json.unmarshal(raw)
} else := raw if {
	is_object(raw)
}

# Wrap a scalar or array into an array.
as_array(x) := x if {
	is_array(x)
} else := [x]

# Simulated clock helpers (UTC).
now_ns := time.parse_rfc3339_ns(input.clock.now)

minutes_of_day(ns) := (c[0] * 60) + c[1] if c := time.clock([ns, "UTC"])

hhmm_minutes(text) := (to_number(parts[0]) * 60) + to_number(parts[1]) if parts := split(text, ":")

in_change_window if {
	w := params.change_window
	time.weekday([now_ns, "UTC"]) == w.weekday
	m := minutes_of_day(now_ns)
	m >= hhmm_minutes(w.start)
	m < hhmm_minutes(w.end)
}

today := sprintf("%04d-%02d-%02d", time.date([now_ns, "UTC"]))

# An approval counts only if it was granted for exactly this changeset, by a human who is not the requester.
valid_approval if {
	some a in input.session.approvals
	a.granted == true
	a.changeset_digest == input.changeset.digest
	is_string(a.approver)
	a.approver != ""
	a.approver != input.request.requester
	not a.approver in params.agent_identities
}

# Granted approvals for this changeset that break segregation of duties.
self_approvals contains a if {
	some a in input.session.approvals
	a.granted == true
	a.changeset_digest == input.changeset.digest
	a.approver == input.request.requester
}

agent_approvals contains a if {
	some a in input.session.approvals
	a.granted == true
	a.changeset_digest == input.changeset.digest
	a.approver in params.agent_identities
}
