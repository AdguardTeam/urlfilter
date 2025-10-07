package lookup_test

import (
	"testing"

	"github.com/AdguardTeam/urlfilter/internal/lookup"
	"github.com/AdguardTeam/urlfilter/internal/uftest"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDomainsTable_Add(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		want assert.BoolAssertionFunc
		name string
		text string
	}{{
		want: assert.False,
		name: "no_domain",
		text: testRuleTextNoDomain,
	}, {
		want: assert.True,
		name: "domain",
		text: testRuleTextWithDomain,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := newStorage(t, tc.text)
			tbl := lookup.NewDomainsTable(s)
			assertRuleIsAdded(t, tbl, s, tc.want)
		})
	}
}

func TestDomainsTable_AppendMatching(t *testing.T) {
	t.Parallel()

	s := newStorage(t, testRuleTextAll)
	tbl := lookup.NewDomainsTable(s)
	loadTable(t, tbl, s)

	testCases := []struct {
		name         string
		urlStr       string
		srcURLStr    string
		wantRuleText string
	}{{
		name:         "no_match",
		urlStr:       testURLStrNoDomain,
		srcURLStr:    testURLStrNoDomain,
		wantRuleText: "",
	}, {
		name:         "no_src",
		urlStr:       uftest.URLStrHostSub,
		srcURLStr:    "",
		wantRuleText: "",
	}, {
		name:         "match_domain",
		urlStr:       uftest.URLStrHostSub,
		srcURLStr:    uftest.URLStrHost,
		wantRuleText: testRuleWithDomain,
	}, {
		name:         "match_subdomain",
		urlStr:       uftest.URLStrHostSub,
		srcURLStr:    uftest.URLStrHostSub,
		wantRuleText: testRuleWithDomain,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := rules.NewRequest(tc.urlStr, tc.srcURLStr, rules.TypeOther)
			assertMatch(t, tbl, r, tc.wantRuleText)
		})
	}
}

func BenchmarkDomainsTable_AppendMatching(b *testing.B) {
	s := newStorage(b, testRuleTextAll)
	tbl := lookup.NewDomainsTable(s)
	loadTable(b, tbl, s)

	r := rules.NewRequest(uftest.URLStrHostSub, uftest.URLStrHost, rules.TypeOther)

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
	//	BenchmarkDomainsTable_AppendMatching-16     	 1000000	      1093 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkDomainsTable_AppendMatching_baseFilter(b *testing.B) {
	s := newStorage(b, string(baseFilterData))
	tbl := lookup.NewDomainsTable(s)
	loadTable(b, tbl, s)

	r := rules.NewRequest(testURLStrBaseFilterDomain, testURLStrBaseFilterDomain, rules.TypeOther)

	var gotRules []*rules.NetworkRule

	// Warmup to fill the slice and the pools.
	gotRules = tbl.AppendMatching(gotRules[:0], r)

	b.ReportAllocs()
	for b.Loop() {
		gotRules = tbl.AppendMatching(gotRules[:0], r)
	}

	require.Len(b, gotRules, 1)

	assertMatch(b, tbl, r, testRuleBaseFilterDomain)

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/urlfilter/internal/lookup
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkDomainsTable_AppendMatching_baseFilter-16     	  744973	      1620 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkDomainsTable_init_baseFilter(b *testing.B) {
	s := newStorage(b, string(baseFilterData))
	tbl := lookup.NewDomainsTable(s)

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
	//	BenchmarkDomainsTable_init_baseFilter/add-16  	      15	  72466138 ns/op	59782924 B/op	  763906 allocs/op
}
