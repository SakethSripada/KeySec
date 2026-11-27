// Package envsync works out what it takes to bring the store in line with a
// .env file, so importing the same file again applies only what changed.
package envsync

import (
	"sort"

	"github.com/sakethsripada/keysec/internal/dotenv"
	"github.com/sakethsripada/keysec/internal/store"
)

// Action is what happens to one secret.
type Action int

// Actions, in the order they are listed.
const (
	Add Action = iota
	Update
	Unchanged
	Remove // imported from this file before, no longer in it
	Skip
)

// Change is the planned action for one name.
type Change struct {
	Name   string
	Action Action
	Value  string // set for Add and Update
	Reason string // set for Skip, and for Update when the old value came from elsewhere
}

// Existing is what the store holds for a name.
type Existing struct {
	Source string
	Value  string
}

// Plan compares the entries of the .env file at source with the store.
// Changes for names in the file come first, in file order, followed by
// removals sorted by name. When a key appears twice the last value wins, as
// it does when the file is loaded by other tools.
func Plan(entries []dotenv.Entry, existing map[string]Existing, source string) []Change {
	last := map[string]string{}
	var order []string
	for _, e := range entries {
		if _, seen := last[e.Key]; !seen {
			order = append(order, e.Key)
		}
		last[e.Key] = e.Value
	}

	var changes []Change
	for _, name := range order {
		value := last[name]
		old, exists := existing[name]
		switch {
		case value == "":
			changes = append(changes, Change{Name: name, Action: Skip, Reason: "empty"})
		case store.ValidateName(name) != nil:
			changes = append(changes, Change{Name: name, Action: Skip, Reason: "invalid name"})
		case !exists:
			changes = append(changes, Change{Name: name, Action: Add, Value: value})
		case old.Value == value:
			changes = append(changes, Change{Name: name, Action: Unchanged})
		default:
			c := Change{Name: name, Action: Update, Value: value}
			if old.Source != source {
				c.Reason = "replaces a value not imported from this file"
			}
			changes = append(changes, c)
		}
	}

	var removed []string
	for name, old := range existing {
		if _, inFile := last[name]; !inFile && old.Source == source {
			removed = append(removed, name)
		}
	}
	sort.Strings(removed)
	for _, name := range removed {
		changes = append(changes, Change{Name: name, Action: Remove})
	}
	return changes
}

// Count returns how many changes have the given action.
func Count(changes []Change, a Action) int {
	n := 0
	for _, c := range changes {
		if c.Action == a {
			n++
		}
	}
	return n
}
