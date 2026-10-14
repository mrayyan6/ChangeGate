package changegate.protected_paths_test

import rego.v1

import data.changegate.protected_paths

ids(rs) := {r.rule_id | some r in rs}

file_action(action, normalized, escapes) := {
	"action": action,
	"args": {"path": normalized},
	"path": {"raw": normalized, "normalized": normalized, "escapes_workspace": escapes},
	"request": data.testdata.noop.request,
	"session": data.testdata.noop.session,
	"clock": data.testdata.noop.clock,
}

test_protected_edits_denied if {
	ids(protected_paths.deny) == {"PP-001"} with input as file_action("edit_file", "approvals/CHG-1.yaml", false)
	ids(protected_paths.deny) == {"PP-001"} with input as file_action("edit_file", ".github/workflows/x.yml", false)
	ids(protected_paths.deny) == {"PP-001"} with input as file_action("edit_file", "policies/x.rego", false)
	ids(protected_paths.deny) == {"PP-001"} with input as file_action("edit_file", "Approvals/X.yaml", false)
	ids(protected_paths.deny) == {"PP-001"} with input as file_action("edit_file", ".GITHUB/CODEOWNERS", false)
	ids(protected_paths.deny) == {"PP-001"} with input as file_action("edit_file", "approvals", false)
}

test_ordinary_edits_allowed if {
	count(protected_paths.deny) == 0 with input as file_action("edit_file", "README.md", false)
	count(protected_paths.deny) == 0 with input as file_action("edit_file", "storage.tf", false)
	count(protected_paths.deny) == 0 with input as file_action("edit_file", "approvals_backup.md", false)
	count(protected_paths.deny) == 0 with input as file_action("edit_file", "docs/policies/notes.md", false)
}

test_reading_protected_paths_allowed if {
	count(protected_paths.deny) == 0 with input as file_action("read_file", "approvals/README.md", false)
}

test_escaping_paths_denied if {
	ids(protected_paths.deny) == {"PP-002"} with input as file_action("edit_file", "secrets.txt", true)
	ids(protected_paths.deny) == {"PP-002"} with input as file_action("read_file", "secrets.txt", true)
}
