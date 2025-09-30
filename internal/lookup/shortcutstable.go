package lookup

import (
	"math"
	"slices"
	"strings"

	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
)

// shortcutLength is the fixed length used to form URL "shortcuts".
const shortcutLength = 5

// shortcut is a single shortcut.
type shortcut string

// shortcutInfo contains the data for a shortcut, including the count of hits.
type shortcutInfo struct {
	ids   []filterlist.StorageID
	count uint64
}

// ShortcutsTable is a [Table] that relies on the rule shortcuts to quickly find
// matching rules:
//
//  1. From the rule, it extracts the longest substring without special
//     characters; this string is the [shortcut].
//  2. It uses a sliding window of [shortcutLength] and puts it into its map.
//  3. When it matches a request, it takes all substrings of length
//     [shortcutsLength] from it and checks if there are any rules in the map.
//
// NOTE: only the rules with a shortcut are eligible for this table.
type ShortcutsTable struct {
	// Storage for the network filtering rules.
	ruleStorage *filterlist.RuleStorage

	// urlBytesPool contains bytes for reuse.
	urlBytesPool *syncutil.Pool[[]byte]

	// shortcutsPool contains slices of shortcuts for reuse.
	shortcutsPool *syncutil.Pool[[]shortcut]

	// shortcuts is the index of a shortcut to its data.
	shortcuts map[shortcut]*shortcutInfo
}

// shortcutsInARuleEst is the estimate for the number of shortcuts in a rule
// based on an analysis of the AdGuard DNS filtering-rule list.
const shortcutsInARuleEst = 16

// urlPoolLen is a length of the URLs pool.
const urlPoolLen = 1024

// NewShortcutsTable creates a new instance of *ShortcutsTable.
func NewShortcutsTable(rs *filterlist.RuleStorage) (s *ShortcutsTable) {
	return &ShortcutsTable{
		ruleStorage:   rs,
		urlBytesPool:  syncutil.NewSlicePool[byte](urlPoolLen),
		shortcutsPool: syncutil.NewSlicePool[shortcut](shortcutsInARuleEst),
		shortcuts:     map[shortcut]*shortcutInfo{},
	}
}

// type check
var _ Table = (*ShortcutsTable)(nil)

// Add implements the [Table] interface for *ShortcutsTable.
func (s *ShortcutsTable) Add(f *rules.NetworkRule, id filterlist.StorageID) (ok bool) {
	shortcutsPtr := s.shortcutsPool.Get()
	defer s.shortcutsPool.Put(shortcutsPtr)

	*shortcutsPtr = appendRuleShortcuts((*shortcutsPtr)[:0], f)
	if len(*shortcutsPtr) == 0 {
		return false
	}

	var minSC shortcut
	var minSCInfo *shortcutInfo
	minCount := uint64(math.MaxUint64)
	for _, sc := range *shortcutsPtr {
		scInfo := s.shortcuts[sc]

		if scInfo == nil {
			minSC = sc
			minSCInfo = &shortcutInfo{}

			break
		}

		if scInfo.count < minCount {
			minCount = scInfo.count
			minSC = sc
			minSCInfo = scInfo
		}
	}

	s.shortcuts[minSC] = minSCInfo
	minSCInfo.count++
	minSCInfo.ids = append(minSCInfo.ids, id)

	return true
}

// AppendMatching implements the [Table] interface for *ShortcutsTable.
func (s *ShortcutsTable) AppendMatching(
	matching []*rules.NetworkRule,
	req *rules.Request,
) (res []*rules.NetworkRule) {
	res = matching

	bufPtr := s.urlBytesPool.Get()
	defer s.urlBytesPool.Put(bufPtr)

	*bufPtr = req.AppendURLData((*bufPtr)[:0], true)

	l := len(*bufPtr)
	if l < shortcutLength {
		return res
	}

	for i := range l - shortcutLength {
		scInfo := s.shortcuts[shortcut((*bufPtr)[i:i+shortcutLength])]
		if scInfo == nil {
			continue
		}

		for _, id := range scInfo.ids {
			rule := s.ruleStorage.RetrieveNetworkRule(id)

			// Make sure that the same rule isn't returned twice.  This happens
			// when the URL has a repeating pattern.  The check is performed
			// rarely and on rather short slices, so it shouldn't cause any
			// performance issues.
			//
			// TODO(a.garipov):  Consider using a pooled set.
			if rule == nil || slices.Contains(res, rule) || !rule.Match(req) {
				continue
			}

			res = append(res, rule)
		}
	}

	return res
}

// appendRuleShortcuts appends shortcuts to scs.  If r is not eligible, res is
// nil.
func appendRuleShortcuts(scs []shortcut, r *rules.NetworkRule) (res []shortcut) {
	if len(r.Shortcut) < shortcutLength {
		return nil
	}

	if isAnyURLShortcut(r) {
		return nil
	}

	res = scs
	for i := range len(r.Shortcut) - shortcutLength {
		s := r.Shortcut[i : i+shortcutLength]
		res = append(res, shortcut(s))
	}

	return res
}

// isAnyURLShortcut checks if the rule potentially matches too many URLs.  It is
// better use another type of lookup table for these kinds of rules.
//
// TODO(a.garipov):  Inspect and optimize.
func isAnyURLShortcut(r *rules.NetworkRule) bool {
	switch scLen := len(r.Shortcut); {
	case
		scLen < len("ws://")+1 && strings.HasPrefix(r.Shortcut, "ws:"),
		scLen < len("wss://")+1 && strings.HasPrefix(r.Shortcut, "wss:"),
		scLen < len("|wss://")+1 && strings.HasPrefix(r.Shortcut, "|ws"),
		scLen < len("https://")+1 && strings.HasPrefix(r.Shortcut, "http"),
		scLen < len("|https://")+1 && strings.HasPrefix(r.Shortcut, "|http"):
		return true
	default:
		return false
	}
}
