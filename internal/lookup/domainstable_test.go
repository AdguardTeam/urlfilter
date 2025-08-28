package lookup_test

import (
	"net/url"
	"testing"

	"github.com/AdguardTeam/urlfilter/internal/lookup"
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
		url          *url.URL
		srcURL       *url.URL
		name         string
		wantRuleText string
	}{{
		url:          testURLNoDomain,
		srcURL:       testURLNoDomain,
		name:         "no_match",
		wantRuleText: "",
	}, {
		url:          testURLWithSubdomain,
		srcURL:       nil,
		name:         "no_src",
		wantRuleText: "",
	}, {
		url:          testURLWithSubdomain,
		srcURL:       testURLWithDomain,
		name:         "match_domain",
		wantRuleText: testRuleWithDomain,
	}, {
		url:          testURLWithSubdomain,
		srcURL:       testURLWithSubdomain,
		name:         "match_subdomain",
		wantRuleText: testRuleWithDomain,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := rules.NewRequest(tc.url, tc.srcURL, rules.TypeOther)
			assertMatch(t, tbl, r, tc.wantRuleText)
		})
	}
}

func BenchmarkDomainsTable_AppendMatching(b *testing.B) {
	s := newStorage(b, testRuleTextAll)
	tbl := lookup.NewDomainsTable(s)
	loadTable(b, tbl, s)

	r := rules.NewRequest(testURLWithSubdomain, testURLWithDomain, rules.TypeOther)

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
	//	BenchmarkDomainsTable_AppendMatching-16     	 6777273	      1510 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkDomainsTable_AppendMatching_baseFilter(b *testing.B) {
	s := newStorage(b, string(baseFilterData))
	tbl := lookup.NewDomainsTable(s)
	loadTable(b, tbl, s)

	r := rules.NewRequest(testURLBaseFilterDomain, testURLBaseFilterDomain, rules.TypeOther)

	gotRules := make([]*rules.NetworkRule, 0, 1)

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
	//	BenchmarkDomainsTable_AppendMatching_baseFilter-16     	 5423517	      2105 ns/op	       0 B/op	       0 allocs/op
}
