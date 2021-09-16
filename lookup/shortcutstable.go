package lookup

import (
	"math"
	"strings"

	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/filterutil"
	"github.com/AdguardTeam/urlfilter/rules"
)

const (
	shortcutLength = 5
)

// ShortcutsTable is a table that relies on the rule "shortcuts" to quickly
// find matching rules. Here's how it works:
//
//   1. We extract from the rule the longest substring without special
//      characters from, this string is called a "shortcut".
//   2. We take a part of it of length "shortcutLength" and put it to the
//      internal hashmap.
//   3. When we match a request, we take all substrings of length
//      "shortcutsLength" from it and check if there're any rules in the
//		hashmap.
//
// Note that only the rules with a shortcut are eligible for this table.
type ShortcutsTable struct {
	// Storage for the network filtering rules.
	ruleStorage *filterlist.RuleStorage

	// Map where the key is the hash of the shortcut and value is a list
	// of rules' indexes.
	shortcutsLookupTable map[uint32][]int64

	// Histogram helps us choose the best shortcut for the shortcuts
	// lookup table.
	shortcutsHistogram map[uint32]int
}

// type check
var _ Table = (*ShortcutsTable)(nil)

// NewShortcutsTable creates a new instance of the ShortcutsTable.
func NewShortcutsTable(rs *filterlist.RuleStorage) (s *ShortcutsTable) {
	return &ShortcutsTable{
		ruleStorage:          rs,
		shortcutsLookupTable: map[uint32][]int64{},
		shortcutsHistogram:   map[uint32]int{},
	}
}

// TryAdd implements the LookupTable interface for *ShortcutsTable.
func (s *ShortcutsTable) TryAdd(f *rules.NetworkRule, storageIdx int64) (ok bool) {
	shortcuts := getRuleShortcuts(f)
	if len(shortcuts) == 0 {
		return false
	}

	// Find the applicable shortcut (the least used)
	var shortcutHash uint32
	minCount := math.MaxInt32
	for _, shortcutToCheck := range shortcuts {
		hash := filterutil.FastHash(shortcutToCheck)
		count, found := s.shortcutsHistogram[hash]
		if !found {
			count = 0
		}
		if count < minCount {
			minCount = count
			shortcutHash = hash
		}
	}

	// Increment the histogram
	s.shortcutsHistogram[shortcutHash] = minCount + 1

	// Add the rule to the lookup table
	rulesIndexes := s.shortcutsLookupTable[shortcutHash]
	rulesIndexes = append(rulesIndexes, storageIdx)
	s.shortcutsLookupTable[shortcutHash] = rulesIndexes

	return true
}

// MatchAll implements the LookupTable interface for *ShortcutsTable.
func (s *ShortcutsTable) MatchAll(r *rules.Request) (result []*rules.NetworkRule) {
	for i := 0; i <= len(r.URLLowerCase)-shortcutLength; i++ {
		// The shortcutsLookupTable contains the shortcuts of rules of
		// fixed length and rules itself.  Go through all the substrings
		// of passed URL having such length to find matching rules.
		hash := filterutil.FastHashBetween(r.URLLowerCase, i, i+shortcutLength)
		matchingRules, ok := s.shortcutsLookupTable[hash]
		if !ok {
			continue
		}

		for _, ruleIdx := range matchingRules {
			rule := s.ruleStorage.RetrieveNetworkRule(ruleIdx)

			// Make sure that the same rule isn't returned twice.
			// This happens when the URL has a repeating pattern.
			// The check is performed rarely and on rather short
			// slices, so it shouldn't cause any performance issues.
			if rule == nil || ruleIn(rule, result) || !rule.Match(r) {
				continue
			}

			result = append(result, rule)
		}
	}

	return result
}

// getRuleShortcuts returns a list of shortcuts that can be used for the lookup table
func getRuleShortcuts(f *rules.NetworkRule) []string {
	if len(f.Shortcut) < shortcutLength {
		return nil
	}

	if isAnyURLShortcut(f) {
		return nil
	}

	var shortcuts []string
	for i := 0; i <= len(f.Shortcut)-shortcutLength; i++ {
		shortcut := f.Shortcut[i : i+shortcutLength]
		shortcuts = append(shortcuts, shortcut)
	}

	return shortcuts
}

// isAnyURLShortcut checks if the rule potentially matches too many URLs.
// We'd better use another type of lookup table for this kind of rules.
func isAnyURLShortcut(f *rules.NetworkRule) bool {
	switch shLen := len(f.Shortcut); {
	case
		shLen < len("ws://")+1 && strings.HasPrefix(f.Shortcut, "ws:"),
		shLen < len("wss://")+1 && strings.HasPrefix(f.Shortcut, "wss:"),
		shLen < len("|wss://")+1 && strings.HasPrefix(f.Shortcut, "|ws"),
		shLen < len("https://")+1 && strings.HasPrefix(f.Shortcut, "http"),
		shLen < len("|https://")+1 && strings.HasPrefix(f.Shortcut, "|http"):
		return true
	default:
		return false
	}
}

// ruleIn checks if the particular rule instance is contained by the slice of
// pointers.
func ruleIn(rule *rules.NetworkRule, rs []*rules.NetworkRule) (ok bool) {
	for _, r := range rs {
		if r == rule {
			return true
		}
	}

	return false
}
