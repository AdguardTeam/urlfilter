package lookup_test

import (
	"net/url"
	"testing"

	"github.com/AdguardTeam/urlfilter/internal/lookup"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeqScanTable_Add(t *testing.T) {
	t.Parallel()

	tbl := &lookup.SeqScanTable{}
	s := newStorage(t, testRuleText)

	require.True(t, t.Run("first", func(t *testing.T) {
		assertRuleIsAdded(t, tbl, s, assert.True)
	}))

	require.True(t, t.Run("same", func(t *testing.T) {
		assertRuleIsAdded(t, tbl, s, assert.False)
	}))
}

func TestSeqScanTable_AppendMatching(t *testing.T) {
	t.Parallel()

	s := newStorage(t, testRuleTextAll)
	tbl := &lookup.SeqScanTable{}
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

func BenchmarkSeqScanTable_AppendMatching(b *testing.B) {
	s := newStorage(b, testRuleTextAll)
	tbl := &lookup.SeqScanTable{}
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
	//	BenchmarkSeqScanTable_AppendMatching-16     	13848735	       850.8 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkSeqScanTable_AppendMatching_baseFilter(b *testing.B) {
	s := newStorage(b, string(baseFilterData))
	tbl := &lookup.SeqScanTable{}
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
	//	BenchmarkSeqScanTable_AppendMatching_baseFilter-16     	    4058	   2928125 ns/op	      79 B/op	       0 allocs/op
}
