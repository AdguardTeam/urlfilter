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

func TestShortcutIndex_Add(t *testing.T) {
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
			idx := lookup.NewShortcutIndex()
			assertRuleIsAdded(t, idx, s, tc.want)
		})
	}
}

func TestShortcutIndex_AppendMatching(t *testing.T) {
	t.Parallel()

	s := newStorage(t, testRuleTextAll)
	idx := lookup.NewShortcutIndex()
	loadIndex(t, idx, s)

	testCases := []struct {
		name   string
		urlStr string
		wantID filterlist.StorageID
	}{{
		name:   "no_match",
		urlStr: uftest.URLStrHostOther,
		wantID: filterlist.StorageID{},
	}, {
		name:   "match",
		urlStr: uftest.URLStrHost,
		wantID: filterlist.NewStorageID(1, 0),
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := rules.NewRequest(tc.urlStr, tc.urlStr, rules.TypeOther)
			assertMatch(t, idx, r, tc.wantID)
		})
	}
}

func BenchmarkShortcutIndex_AppendMatching(b *testing.B) {
	s := newStorage(b, testRuleTextAll)
	idx := lookup.NewShortcutIndex()
	loadIndex(b, idx, s)

	r := rules.NewRequest(uftest.URLStrHost, uftest.URLStrHost, rules.TypeOther)

	var gotIDs []filterlist.StorageID

	// Warmup to fill the slice and the pools.
	gotIDs = idx.AppendMatching(gotIDs[:0], r)

	b.ReportAllocs()
	for b.Loop() {
		gotIDs = idx.AppendMatching(gotIDs[:0], r)
	}

	require.Len(b, gotIDs, 1)

	assertMatch(b, idx, r, filterlist.NewStorageID(1, 0))

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/urlfilter/internal/lookup
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkShortcutIndex_AppendMatching-16  	 6299392	       191.3 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkShortcutIndex_AppendMatching_baseFilter(b *testing.B) {
	s := newStorage(b, string(baseFilterData))
	idx := lookup.NewShortcutIndex()
	loadIndex(b, idx, s)

	r := rules.NewRequest(testURLStrBaseFilterDomain, testURLStrBaseFilterDomain, rules.TypeOther)

	var gotIDs []filterlist.StorageID

	// Warmup to fill the slice and the pools.
	gotIDs = idx.AppendMatching(gotIDs[:0], r)

	b.ReportAllocs()
	for b.Loop() {
		gotIDs = idx.AppendMatching(gotIDs[:0], r)
	}

	matched := false
	for _, got := range gotIDs {
		r := s.RetrieveNetworkRule(got)
		require.NotNil(b, r)
		matched = matched || r.Text() == testRuleBaseFilterDomain
	}

	assert.True(b, matched)

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/urlfilter/internal/lookup
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkShortcutIndex_AppendMatching_baseFilter-16  	 1000000	      1039 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkShortcutIndex_init_baseFilter(b *testing.B) {
	s := newStorage(b, string(baseFilterData))
	idx := lookup.NewShortcutIndex()

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
	//	BenchmarkShortcutIndex_init_baseFilter/add-16         	      12	  96832984 ns/op	60934741 B/op	  821825 allocs/op
}
