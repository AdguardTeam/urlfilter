package lookup_test

import (
	"testing"

	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/internal/lookup"
	"github.com/AdguardTeam/urlfilter/internal/uftest"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDomainIndex_Add(t *testing.T) {
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
			idx := lookup.NewDomainIndex()
			assertRuleIsAdded(t, idx, s, tc.want)
		})
	}
}

func TestDomainIndex_AppendMatching(t *testing.T) {
	t.Parallel()

	s := newStorage(t, testRuleTextAll)
	idx := lookup.NewDomainIndex()
	loadIndex(t, idx, s)

	testCases := []struct {
		name      string
		urlStr    string
		srcURLStr string
		wantID    filterlist.StorageID
	}{{
		name:      "no_src",
		urlStr:    uftest.URLStrHostSub,
		srcURLStr: "",
		wantID:    filterlist.StorageID{},
	}, {
		name:      "match_domain",
		urlStr:    uftest.URLStrHostSub,
		srcURLStr: uftest.URLStrHost,
		wantID:    filterlist.NewStorageID(1, 54),
	}, {
		name:      "match_subdomain",
		urlStr:    uftest.URLStrHostSub,
		srcURLStr: uftest.URLStrHostSub,
		wantID:    filterlist.NewStorageID(1, 54),
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := rules.NewRequest(tc.urlStr, tc.srcURLStr, rules.TypeOther)
			assertMatch(t, idx, r, tc.wantID)
		})
	}
}

func BenchmarkDomainIndex_AppendMatching(b *testing.B) {
	s := newStorage(b, testRuleTextAll)
	idx := lookup.NewDomainIndex()
	loadIndex(b, idx, s)

	r := rules.NewRequest(uftest.URLStrHostSub, uftest.URLStrHost, rules.TypeOther)

	var gotIDs []filterlist.StorageID

	// Warmup to fill the slice and the pools.
	gotIDs = idx.AppendMatching(gotIDs[:0], r)

	b.ReportAllocs()
	for b.Loop() {
		gotIDs = idx.AppendMatching(gotIDs[:0], r)
	}

	require.Len(b, gotIDs, 1)

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/urlfilter/internal/lookup
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkDomainIndex_AppendMatching-16     	18093811	     65.43 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkDomainIndex_AppendMatching_baseFilter(b *testing.B) {
	s := newStorage(b, string(baseFilterData))
	idx := lookup.NewDomainIndex()
	loadIndex(b, idx, s)

	r := rules.NewRequest(testURLStrBaseFilterDomain, testURLStrBaseFilterDomain, rules.TypeOther)

	var gotIDs []filterlist.StorageID

	// Warmup to fill the slice and the pools.
	gotIDs = idx.AppendMatching(gotIDs[:0], r)

	b.ReportAllocs()
	for b.Loop() {
		gotIDs = idx.AppendMatching(gotIDs[:0], r)
	}

	require.Len(b, gotIDs, 2)

	assert.Equal(b, filterlist.NewStorageID(1, 6605416), gotIDs[0])
	assert.Equal(b, filterlist.NewStorageID(1, 6615547), gotIDs[1])

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/urlfilter/internal/lookup
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkDomainIndex_AppendMatching_baseFilter-16     	11390737	     105.9 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkDomainIndex_init_baseFilter(b *testing.B) {
	s := newStorage(b, string(baseFilterData))
	idx := lookup.NewDomainIndex()

	// Warmup to fill the slice and the pools.
	loadIndex(b, idx, s)

	require.True(b, b.Run("add", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			idx.Reset()
			loadIndex(b, idx, s)
		}
	}))

	// TODO(a.garipov):  Benchmark against decoding of a binary format.

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/urlfilter/internal/lookup
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkDomainIndex_init_baseFilter/add-16  	      14	  71985505 ns/op	59814161 B/op	  763911 allocs/op
}
