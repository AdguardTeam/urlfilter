package lookup_test

import (
	"testing"

	"github.com/AdguardTeam/urlfilter/internal/lookup"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShortcutsTable_TryAdd(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		want assert.BoolAssertionFunc
		name string
		text string
	}{{
		want: assert.False,
		name: "no_shortcuts",
		text: testRuleTextNoShortcutsTiny,
	}, {
		want: assert.False,
		name: "no_shortcuts_url",
		text: testRuleTextNoShortcutsURL,
	}, {
		want: assert.True,
		name: "success",
		text: testRuleText,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := newStorage(t, tc.text)
			tbl := lookup.NewShortcutsTable(s)
			assertRuleIsAdded(t, tbl, s, tc.want)
		})
	}
}

func TestShortcutsTable_MatchAll(t *testing.T) {
	t.Parallel()

	s := newStorage(t, testRuleTextAll)
	tbl := lookup.NewShortcutsTable(s)
	loadTable(t, tbl, s)

	testCases := []struct {
		name         string
		urlStr       string
		wantRuleText string
	}{{
		name:         "no_match",
		urlStr:       testURLStrNoMatch,
		wantRuleText: "",
	}, {
		name:         "match",
		urlStr:       testURLStrWithDomain,
		wantRuleText: testRule,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := rules.NewRequest(tc.urlStr, tc.urlStr, rules.TypeOther)
			assertMatch(t, tbl, r, tc.wantRuleText)
		})
	}
}

func BenchmarkShortcutTable_MatchAll(b *testing.B) {
	s := newStorage(b, testRuleTextAll)
	tbl := lookup.NewShortcutsTable(s)
	loadTable(b, tbl, s)

	r := rules.NewRequest(testURLStrWithDomain, testURLStrWithDomain, rules.TypeOther)

	var gotRules []*rules.NetworkRule

	b.ReportAllocs()
	for b.Loop() {
		gotRules = tbl.MatchAll(r)
	}

	require.Len(b, gotRules, 1)

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/urlfilter/internal/lookup
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkShortcutTable_MatchAll-16    	34789922	      1061 ns/op	       8 B/op	       1 allocs/op
}

func BenchmarkShortcutTable_MatchAll_baseFilter(b *testing.B) {
	s := newStorage(b, string(baseFilterData))
	tbl := lookup.NewShortcutsTable(s)
	loadTable(b, tbl, s)

	r := rules.NewRequest(testURLStrBaseFilterDomain, testURLStrBaseFilterDomain, rules.TypeOther)

	var gotRules []*rules.NetworkRule

	b.ReportAllocs()
	for b.Loop() {
		gotRules = tbl.MatchAll(r)
	}

	matched := false
	for _, got := range gotRules {
		matched = matched || got.Text() == testRuleBaseFilterDomain
	}

	assert.True(b, matched)

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/urlfilter/internal/lookup
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkShortcutTable_MatchAll_baseFilter-16    	  101490	     10900 ns/op	      57 B/op	       3 allocs/op
}
