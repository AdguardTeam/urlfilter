package lookup

import (
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
)

// SeqScanTable is a slice of network rules that are scanned sequentially.  Use
// this for the rules that are not eligible for other tables.
type SeqScanTable struct {
	rules []*rules.NetworkRule
}

// type check
var _ Table = (*SeqScanTable)(nil)

// Add implements the [Table] interface for *SeqScanTable.
func (s *SeqScanTable) Add(f *rules.NetworkRule, _ filterlist.StorageID) (ok bool) {
	if containsRule(s.rules, f) {
		return false
	}

	s.rules = append(s.rules, f)

	return true
}

// AppendMatching implements the [Table] interface for *SeqScanTable.
func (s *SeqScanTable) AppendMatching(
	matching []*rules.NetworkRule,
	r *rules.Request,
) (res []*rules.NetworkRule) {
	res = matching
	for _, rule := range s.rules {
		if rule.Match(r) {
			res = append(res, rule)
		}
	}

	return res
}

// containsRule is a helper function that checks if the specified rule is
// already in the array.
//
// TODO(a.garipov):  Consider replacing with a set lookup.
func containsRule(rules []*rules.NetworkRule, r *rules.NetworkRule) (ok bool) {
	if rules == nil {
		return false
	}

	for _, rule := range rules {
		if rule.String() == r.String() {
			return true
		}
	}

	return false
}
