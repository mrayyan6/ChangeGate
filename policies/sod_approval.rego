# Segregation of duties: privileged changes need an approval from someone other than the requester.
# An approval counts only if it was granted for exactly the pending changeset (see lib.valid_approval).
package changegate.sod_approval

import rego.v1

import data.changegate.lib

# Changes that need an approval: privileged resource types, or listed attributes of other types.
privileged contains c if {
	some c in lib.changes
	c.type in lib.params.approval_required_types
}

privileged contains c if {
	some c in lib.changes
	attrs := object.get(lib.params.approval_required_attributes, c.type, [])
	some a in c.changed_attributes
	a in attrs
}

# SOD-001: approval required.
require_approval contains {
	"rule_id": "SOD-001",
	"policy": "sod_approval",
	"effect": "require_approval",
	"severity": "high",
	"resource": c.address,
	"message": sprintf(
		"%s (%s) is a privileged change and needs approval from someone other than the requester %s.",
		[c.address, c.action, input.request.requester],
	),
	"hint": "Call request_approval with a short reason. A person other than the requester must approve; then apply again without further edits.",
} if {
	lib.is_apply
	some c in privileged
	not lib.valid_approval
}

# SOD-002: the only approval for this change comes from the requester.
deny contains {
	"rule_id": "SOD-002",
	"policy": "sod_approval",
	"effect": "deny",
	"severity": "high",
	"resource": null,
	"message": sprintf("The approval for this change was given by the requester %s, which breaks segregation of duties.", [input.request.requester]),
	"hint": "A self approval is not valid. Ask for approval from a different person through request_approval.",
} if {
	lib.is_apply
	count(lib.self_approvals) > 0
	not lib.valid_approval
}

# SOD-003: the only approval for this change comes from an agent.
deny contains {
	"rule_id": "SOD-003",
	"policy": "sod_approval",
	"effect": "deny",
	"severity": "high",
	"resource": null,
	"message": "The approval for this change was given by an automated agent, and agents cannot approve changes.",
	"hint": "Only a human approver other than the requester can approve. Use request_approval.",
} if {
	lib.is_apply
	count(lib.agent_approvals) > 0
	not lib.valid_approval
}
