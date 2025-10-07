package lookup_test

import (
	"testing"

	"github.com/AdguardTeam/urlfilter/internal/lookup"
	"github.com/AdguardTeam/urlfilter/internal/uftest"
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
		name         string
		urlStr       string
		wantRuleText string
	}{{
		name:         "no_match",
		urlStr:       uftest.URLStrHostOther,
		wantRuleText: "",
	}, {
		name:         "match",
		urlStr:       uftest.URLStrHost,
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

func BenchmarkShortcutsTable_AppendMatching(b *testing.B) {
	s := newStorage(b, testRuleTextAll)
	tbl := lookup.NewShortcutsTable(s)
	loadTable(b, tbl, s)

	r := rules.NewRequest(uftest.URLStrHost, uftest.URLStrHost, rules.TypeOther)

	var gotRules []*rules.NetworkRule

	// Warmup to fill the slice and the pools.
	gotRules = tbl.AppendMatching(gotRules[:0], r)

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
	//	BenchmarkShortcutsTable_AppendMatching-16    	 1000000	      1088 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkShortcutsTable_AppendMatching_baseFilter(b *testing.B) {
	s := newStorage(b, string(baseFilterData))
	tbl := lookup.NewShortcutsTable(s)
	loadTable(b, tbl, s)

	r := rules.NewRequest(testURLStrBaseFilterDomain, testURLStrBaseFilterDomain, rules.TypeOther)

	var gotRules []*rules.NetworkRule

	// Warmup to fill the slice and the pools.
	gotRules = tbl.AppendMatching(gotRules[:0], r)

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
	//	BenchmarkShortcutsTable_AppendMatching_baseFilter-16    	   98634	     12114 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkShortcutsTable_init_baseFilter(b *testing.B) {
	s := newStorage(b, string(baseFilterData))
	tbl := lookup.NewShortcutsTable(s)

	// Warmup to fill the slice and the pools.
	loadTable(b, tbl, s)

	require.True(b, b.Run("add", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			tbl.Reset()
			loadTable(b, tbl, s)
		}
	}))

	// TODO(a.garipov):  Benchmark against decoding of a binary format.

	// Most recent results:
	//	BenchmarkShortcutsTable_init_baseFilter/add-16         	      12	 100024476 ns/op	63062610 B/op	  888174 allocs/op
}
