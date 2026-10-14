# Change window: an apply outside the weekly window needs an emergency approval (CW-001).
package changegate.change_window

import rego.v1

import data.changegate.lib

# The configured window as text, for example "Saturday 02:00 to 04:00 UTC". Without a usable window
# every apply needs approval, so the fallback text keeps the rule firing (fail closed).
window_text := text if {
	w := lib.params.change_window
	text := sprintf("%s %s to %s %s", [w.weekday, w.start, w.end, w.timezone])
} else := "the configured change window"

# The simulated time as text, for example "Wednesday 2026-10-14 15:00 UTC".
now_text := text if {
	hm := time.clock([lib.now_ns, "UTC"])
	text := sprintf("%s %s %02d:%02d UTC", [time.weekday([lib.now_ns, "UTC"]), lib.today, hm[0], hm[1]])
} else := "an unreadable simulated time"

addresses := sort([c.address | some c in lib.changes])

# The pending changes for the message, at most five addresses.
targets := text if {
	count(addresses) <= 5
	text := concat(", ", addresses)
} else := text if {
	text := sprintf("%s and %d more", [concat(", ", array.slice(addresses, 0, 5)), count(addresses) - 5])
}

require_approval contains {
	"rule_id": "CW-001",
	"policy": "change_window",
	"effect": "require_approval",
	"severity": "high",
	"resource": null,
	"message": sprintf("Applying %s at %s is outside the change window (%s).", [targets, now_text, window_text]),
	"hint": sprintf("Apply during the change window (%s), or for an emergency change call request_approval with the business reason and then apply again without further edits.", [window_text]),
} if {
	lib.is_apply
	lib.n_changes > 0
	not lib.in_change_window
	not lib.valid_approval
}
