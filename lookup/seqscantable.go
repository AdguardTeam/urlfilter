package lookup

import (
	"github.com/AdguardTeam/urlfilter/rules"
)

// SeqScanTable is basically just a list of network rules that are scanned
// sequentially.  Here we put the rules that are not eligible for other tables.
type SeqScanTable struct {
	rules []*rules.NetworkRule
}

// type check
var _ Table = (*SeqScanTable)(nil)

// TryAdd implements the LookupTable interface for *SeqScanTable.
func (s *SeqScanTable) TryAdd(f *rules.NetworkRule, _ int64) (ok bool) {
	if !containsRule(s.rules, f) {
		s.rules = append(s.rules, f)
		return true
	}
	return false
}

// MatchAll implements the LookupTable interface for *SeqScanTable.
func (s *SeqScanTable) MatchAll(r *rules.Request) (result []*rules.NetworkRule) {
	for _, rule := range s.rules {
		if rule.Match(r) {
			result = append(result, rule)
		}
	}
	return result
}

// containsRule is a helper function that checks if the specified rule is
// already in the array.
func containsRule(rules []*rules.NetworkRule, r *rules.NetworkRule) (ok bool) {
	if rules == nil {
		return false
	}

	for _, rule := range rules {
		if rule.RuleText == r.RuleText {
			return true
		}
	}

	return false
}
