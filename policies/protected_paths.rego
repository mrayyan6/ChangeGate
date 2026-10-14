# Protected paths: the agent may not edit files owned by other teams, or leave the repository.
package changegate.protected_paths

import rego.v1

import data.changegate.lib

target := lower(input.path.normalized)

# "approvals/x" and the folder "approvals" itself are protected; "approvals_backup/x" is not.
under(prefix) if startswith(target, lower(prefix))

under(prefix) if target == trim_suffix(lower(prefix), "/")

# PP-001: editing a protected path.
deny contains {
	"rule_id": "PP-001",
	"policy": "protected_paths",
	"effect": "deny",
	"severity": "critical",
	"resource": input.path.normalized,
	"message": sprintf("%s is under the protected path %s and may not be edited by the agent.", [input.path.normalized, prefix]),
	"hint": "Leave this folder unchanged: it is owned by another team. Approvals come only from request_approval, never from files the agent writes.",
} if {
	input.action == "edit_file"
	some prefix in lib.params.protected_paths
	under(prefix)
}

# PP-002: a file path that escapes the workspace.
deny contains {
	"rule_id": "PP-002",
	"policy": "protected_paths",
	"effect": "deny",
	"severity": "high",
	"resource": input.path.raw,
	"message": sprintf("The path %s points outside the repository.", [input.path.raw]),
	"hint": "Stay inside the repository: use paths relative to its root, such as storage.tf.",
} if {
	input.action in {"edit_file", "read_file"}
	input.path.escapes_workspace == true
}
