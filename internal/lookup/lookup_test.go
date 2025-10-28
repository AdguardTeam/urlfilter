package lookup_test

import (
	"net/url"
	"os"
	"testing"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/internal/uftest"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Common domains for tests.
const (
	testDomainNoMod = "nomod." + uftest.Host
)

// Common rules for tests.
const (
	testRule                = "||" + uftest.Host + "^"
	testRuleNoDomain        = "||" + testDomainNoMod + "^"
	testRuleNoShortcutsTiny = "||tiny^"
	testRuleNoShortcutsURL  = "|ws://^"
	testRuleWithDomain      = "||" + uftest.HostSub + "^$domain=" + uftest.Host
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

// Common constants from the AdGuard Base Filter for tests.
//
// Keep in sync with ../../testdata/adguard_base_filter.txt.
const (
	testRuleBaseFilterDomain = "@@||googleads.g.doubleclick.net/ads/preferences/" +
		"$domain=googleads.g.doubleclick.net"
)

// Common URLs from the AdGuard Base Filter for tests.
//
// Keep in sync with ../../testdata/adguard_base_filter.txt.
var testURLBaseFilterDomain = &url.URL{
	Scheme: urlutil.SchemeHTTPS,
	Host:   "googleads.g.doubleclick.net",
	Path:   "/ads/preferences/",
}

// Common URLs for tests.
var (
	testURLNoMatch = &url.URL{
		Scheme: urlutil.SchemeHTTPS,
		Host:   "no-match.example",
	}

	testURLWithDomain = &url.URL{
		Scheme: urlutil.SchemeHTTPS,
		Host:   uftest.Host,
	}

	testURLWithSubdomain = &url.URL{
		Scheme: urlutil.SchemeHTTPS,
		Host:   uftest.HostSub,
	}
)

// newStorage is a helper that creates a rule storage for tests with the given
// rule text.
func newStorage(tb testing.TB, text string) (s *filterlist.RuleStorage) {
	tb.Helper()

	l := filterlist.NewString(&filterlist.StringConfig{
		RulesText: text,
		ID:        uftest.ListID1,
	})

	s, err := filterlist.NewRuleStorage([]filterlist.Interface{l})
	require.NoError(tb, err)

	return s
}

// testBaseFilterData is the data from AdGuard Base Filter.
var testBaseFilterData = errors.Must(os.ReadFile("../../testdata/adguard_base_filter.txt"))

// newBaseFilterStorage is a helper that creates a rule storage for tests with
// the data from AdGuard Base Filter.
func newBaseFilterStorage(tb testing.TB) (s *filterlist.RuleStorage) {
	tb.Helper()

	l := filterlist.NewBytes(&filterlist.BytesConfig{
		RulesText: testBaseFilterData,
		ID:        uftest.ListID2,
	})

	s, err := filterlist.NewRuleStorage([]filterlist.Interface{l})
	require.NoError(tb, err)

	return s
}

// index is the interface for all indexes.
type index interface {
	Add(r *rules.NetworkRule, id filterlist.StorageID) (ok bool)
	AppendMatching(orig []filterlist.StorageID, r *rules.Request) (res []filterlist.StorageID)
}

// assertMatch is a helper for matching a single rule in the index or, if
// wantRuleText is empty, that no rules are returned.
func assertMatch(tb testing.TB, tbl index, r *rules.Request, wantID filterlist.StorageID) {
	tb.Helper()

	gotIDs := tbl.AppendMatching(nil, r)

	if wantID == (filterlist.StorageID{}) {
		assert.Empty(tb, gotIDs)

		return
	}

	require.Len(tb, gotIDs, 1)

	assert.Equal(tb, wantID, gotIDs[0])
}

// assertRuleIsAdded is a helper to assert if a single rule has been added to
// idx.
func assertRuleIsAdded(
	tb testing.TB,
	idx index,
	s *filterlist.RuleStorage,
	want assert.BoolAssertionFunc,
) {
	tb.Helper()

	var num int
	sc := s.NewRuleStorageScanner()
	for sc.Scan() {
		num++

		r, id := sc.Rule()
		want(tb, idx.Add(r.(*rules.NetworkRule), id))
	}

	assert.Equal(tb, 1, num)
}

// loadIndex is a helper that loads rules from s to idx.
func loadIndex(tb testing.TB, idx index, s *filterlist.RuleStorage) {
	tb.Helper()

	sc := s.NewRuleStorageScanner()
	for sc.Scan() {
		r, id := sc.Rule()
		if nr, ok := r.(*rules.NetworkRule); ok {
			_ = idx.Add(nr, id)
		}
	}
}
