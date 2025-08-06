// Package lookup implements index structures that we use to improve matching
// speed in the engines.
package lookup

import "github.com/AdguardTeam/urlfilter/rules"

// Table is a common interface for all lookup tables.
type Table interface {
	// TryAdd attempts to add the rule to the lookup table.
	// It returns true/false depending on whether the rule is eligible for
	// this lookup table.
	TryAdd(f *rules.NetworkRule, storageIdx int64) (ok bool)

	// MatchAll finds all matching rules from this lookup table.
	MatchAll(r *rules.Request) (result []*rules.NetworkRule)
}
