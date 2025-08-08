package lookup_test

import (
	"os"
	"testing"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/internal/lookup"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Common domains for tests.
const (
	testDomain      = "domain.example"
	testDomainNoMod = "nomod.domain.example"
	testDomainSub   = "sub.domain.example"
)

// Common rules for tests.
const (
	testRule                = "||" + testDomain + "^"
	testRuleNoDomain        = "||" + testDomainNoMod + "^"
	testRuleNoShortcutsTiny = "||tiny^"
	testRuleNoShortcutsURL  = "|ws://^"
	testRuleWithDomain      = "||" + testDomainSub + "^$domain=" + testDomain
)

// Common text rules for tests.
const (
	testRuleText                = testRule + "\n"
	testRuleTextNoDomain        = testRuleNoDomain + "\n"
	testRuleTextNoShortcutsTiny = testRuleNoShortcutsTiny + "\n"
	testRuleTextNoShortcutsURL  = testRuleNoShortcutsURL + "\n"
	testRuleTextWithDomain      = testRuleWithDomain + "\n"

	testRuleTextAll = testRuleText +
		testRuleTextNoDomain +
		testRuleTextNoShortcutsTiny +
		testRuleTextNoShortcutsURL +
		testRuleTextWithDomain
)

// Common URL strings for tests.
const (
	testURLStrNoDomain      = "https://" + testDomainNoMod + "/"
	testURLStrNoMatch       = "https://no-match.example/"
	testURLStrWithDomain    = "https://" + testDomain + "/"
	testURLStrWithSubdomain = "https://" + testDomainSub + "/"
)

// Common constants from the AdGuard Base Filter for tests.
//
// Keep in sync with ../../testdata/adguard_base_filter.txt.
const (
	testRuleBaseFilterDomain = "@@||googleads.g.doubleclick.net/ads/preferences/" +
		"$domain=googleads.g.doubleclick.net"

	testURLStrBaseFilterDomain = "https://googleads.g.doubleclick.net/ads/preferences/"
)

// baseFilterData is the data from AdGuard Base Filter.
var baseFilterData = errors.Must(os.ReadFile("../../testdata/adguard_base_filter.txt"))

// newStorage is a helper that creates a rule storage for tests with the given
// rule text.
func newStorage(tb testing.TB, text string) (s *filterlist.RuleStorage) {
	tb.Helper()

	l := &filterlist.StringRuleList{
		RulesText: text,
	}

	s, err := filterlist.NewRuleStorage([]filterlist.RuleList{l})
	require.NoError(tb, err)

	return s
}

// assertMatch is a helper for matching a single rule in the table or, if
// wantRuleText is empty, that no rules are returned.
func assertMatch(
	tb testing.TB,
	tbl lookup.Table,
	r *rules.Request,
	wantRuleText string,
) {
	tb.Helper()

	gotRules := tbl.MatchAll(r)

	if wantRuleText == "" {
		assert.Empty(tb, gotRules)

		return
	}

	require.Len(tb, gotRules, 1)

	assert.Equal(tb, wantRuleText, gotRules[0].RuleText)
}

// assertRuleIsAdded is a helper to assert if a single rule has been added to
// tbl.
func assertRuleIsAdded(
	tb testing.TB,
	tbl lookup.Table,
	s *filterlist.RuleStorage,
	want assert.BoolAssertionFunc,
) {
	tb.Helper()

	var num int
	sc := s.NewRuleStorageScanner()
	for sc.Scan() {
		num++

		r, idx := sc.Rule()
		want(tb, tbl.TryAdd(r.(*rules.NetworkRule), idx))
	}

	assert.Equal(tb, 1, num)
}

// loadTable is a helper that loads rules from s to tbl.
func loadTable(tb testing.TB, tbl lookup.Table, s *filterlist.RuleStorage) {
	tb.Helper()

	sc := s.NewRuleStorageScanner()
	for sc.Scan() {
		r, idx := sc.Rule()
		if nr, ok := r.(*rules.NetworkRule); ok {
			_ = tbl.TryAdd(nr, idx)
		}
	}
}
