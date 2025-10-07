package lookup_test

import (
	"testing"

	"github.com/AdguardTeam/urlfilter/internal/lookup"
	"github.com/AdguardTeam/urlfilter/internal/uftest"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeqScanTable_Add(t *testing.T) {
	t.Parallel()

	tbl := lookup.NewSeqScanTable()
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
	tbl := lookup.NewSeqScanTable()
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

func BenchmarkSeqScanTable_AppendMatching(b *testing.B) {
	s := newStorage(b, testRuleTextAll)
	tbl := lookup.NewSeqScanTable()
	loadTable(b, tbl, s)

	r := rules.NewRequest(uftest.URLStrHost, uftest.URLStrHost, rules.TypeOther)

	var gotRules []*rules.NetworkRule

	// Warmup to fill the slice.
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
	//	BenchmarkSeqScanTable_AppendMatching-16     	 1359025	       871.1 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkSeqScanTable_AppendMatching_baseFilter(b *testing.B) {
	s := newStorage(b, string(baseFilterData))
	tbl := lookup.NewSeqScanTable()
	loadTable(b, tbl, s)

	r := rules.NewRequest(testURLStrBaseFilterDomain, testURLStrBaseFilterDomain, rules.TypeOther)

	var gotRules []*rules.NetworkRule

	// Warmup to fill the slice.
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
	//	BenchmarkSeqScanTable_AppendMatching_baseFilter-16    	     392	   3057949 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkSeqScanTable_init_baseFilter(b *testing.B) {
	s := newStorage(b, string(baseFilterData))
	tbl := lookup.NewSeqScanTable()

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
	//	BenchmarkSeqScanTable_init_baseFilter/add-16         	      12	  85245146 ns/op	59263900 B/op	  752826 allocs/op
}
