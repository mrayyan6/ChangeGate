# Aggregates every ChangeGate policy into one decision.
# Precedence: deny over require_approval over allow.
package changegate.main

import rego.v1

import data.changegate.blast_radius
import data.changegate.change_window
import data.changegate.cumulative
import data.changegate.lib
import data.changegate.protected_paths
import data.changegate.security
import data.changegate.sod_approval

# A pending apply whose changes could not be computed at all is refused.
integrity_deny contains {
	"rule_id": "CS-001",
	"policy": "integrity",
	"effect": "deny",
	"severity": "high",
	"resource": null,
	"message": "The change could not be planned or parsed, so it cannot be checked or applied.",
	"hint": "Run terraform_plan, fix the reported errors, then apply again.",
} if {
	lib.is_apply
	not input.changeset
}

integrity_deny contains {
	"rule_id": "CS-001",
	"policy": "integrity",
	"effect": "deny",
	"severity": "high",
	"resource": null,
	"message": "The change could not be planned or parsed, so it cannot be checked or applied.",
	"hint": "Run terraform_plan, fix the reported errors, then apply again.",
} if {
	lib.is_apply
	count(input.changeset.errors) > 0
	count(input.changeset.changes) == 0
}

denies := ((((security.deny | blast_radius.deny) | cumulative.deny) | protected_paths.deny) | sod_approval.deny) | integrity_deny

approval_reasons := change_window.require_approval | sod_approval.require_approval

decision := {"decision": "deny", "reasons": sort([r | some r in denies])} if {
	count(denies) > 0
}

decision := {"decision": "require_approval", "reasons": sort([r | some r in approval_reasons])} if {
	count(denies) == 0
	count(approval_reasons) > 0
}

decision := {"decision": "allow", "reasons": []} if {
	count(denies) == 0
	count(approval_reasons) == 0
}
