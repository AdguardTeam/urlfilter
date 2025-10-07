package lookup

import (
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
)

// SeqScanTable is a slice of network rules that are scanned sequentially.  Use
// this for the rules that are not eligible for other tables.
type SeqScanTable struct {
	set   *container.MapSet[string]
	rules []*rules.NetworkRule
}

// NewSeqScanTable creates a new properly initialized *SeqScanTable.
func NewSeqScanTable() (t *SeqScanTable) {
	return &SeqScanTable{
		set: container.NewMapSet[string](),
	}
}

// type check
var _ Table = (*SeqScanTable)(nil)

// Add implements the [Table] interface for *SeqScanTable.
func (t *SeqScanTable) Add(r *rules.NetworkRule, _ filterlist.StorageID) (ok bool) {
	s := r.String()
	if t.set.Has(s) {
		return false
	}

	t.set.Add(s)

	// NOTE:  Keep the order of the rules for e.g. $dnsrewrite rules with CNAME
	// RR type and short domain names.
	t.rules = append(t.rules, r)

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

// Reset prepares t for reuse.
func (t *SeqScanTable) Reset() {
	t.set.Clear()
	t.rules = t.rules[:0]
}
