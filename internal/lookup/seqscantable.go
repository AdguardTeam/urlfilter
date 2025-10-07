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
func (t *SeqScanTable) Add(f *rules.NetworkRule, _ filterlist.StorageID) (ok bool) {
	if containsRule(t.rules, f) {
		return false
	}

	t.rules = append(t.rules, f)

	return true
}

// AppendMatching implements the [Table] interface for *SeqScanTable.
func (t *SeqScanTable) AppendMatching(
	matching []*rules.NetworkRule,
	r *rules.Request,
) (res []*rules.NetworkRule) {
	res = matching
	for _, rule := range t.rules {
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

// Reset prepares t for reuse.
func (t *SeqScanTable) Reset() {
	t.rules = t.rules[:0]
}
