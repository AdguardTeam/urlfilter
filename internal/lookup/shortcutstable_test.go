package lookup_test

import (
	"net/url"
	"testing"

	"github.com/AdguardTeam/urlfilter/internal/lookup"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShortcutsTable_Add(t *testing.T) {
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

func TestShortcutsTable_AppendMatching(t *testing.T) {
	t.Parallel()

	s := newStorage(t, testRuleTextAll)
	tbl := lookup.NewShortcutsTable(s)
	loadTable(t, tbl, s)

	testCases := []struct {
		url          *url.URL
		name         string
		wantRuleText string
	}{{
		url:          testURLNoMatch,
		name:         "no_match",
		wantRuleText: "",
	}, {
		url:          testURLWithDomain,
		name:         "match",
		wantRuleText: testRule,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := rules.NewRequest(tc.url, tc.url, rules.TypeOther)
			assertMatch(t, tbl, r, tc.wantRuleText)
		})
	}
}

func BenchmarkShortcutTable_AppendMatching(b *testing.B) {
	s := newStorage(b, testRuleTextAll)
	tbl := lookup.NewShortcutsTable(s)
	loadTable(b, tbl, s)

	r := rules.NewRequest(testURLWithDomain, testURLWithDomain, rules.TypeOther)

	gotRules := make([]*rules.NetworkRule, 0, 1)

	b.ReportAllocs()
	for b.Loop() {
		gotRules = tbl.AppendMatching(gotRules[:0], r)
	}

	require.Len(b, gotRules, 1)

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/urlfilter/internal/lookup
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkShortcutTable_AppendMatching-16    	10421620	      1085 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkShortcutTable_AppendMatching_baseFilter(b *testing.B) {
	s := newStorage(b, string(baseFilterData))
	tbl := lookup.NewShortcutsTable(s)
	loadTable(b, tbl, s)

	r := rules.NewRequest(testURLBaseFilterDomain, testURLBaseFilterDomain, rules.TypeOther)

	gotRules := make([]*rules.NetworkRule, 0, 1)

	b.ReportAllocs()
	for b.Loop() {
		gotRules = tbl.AppendMatching(gotRules[:0], r)
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
	//	BenchmarkShortcutTable_AppendMatching_baseFilter-16    	 1000000	     10506 ns/op	       0 B/op	       0 allocs/op
}
