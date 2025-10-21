package lookup_test

import (
	"bufio"
	"bytes"
	"regexp"
	"testing"

	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/internal/lookup"
	"github.com/AdguardTeam/urlfilter/internal/uftest"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/fxamacker/cbor/v2"
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

func TestDomainIndex_AppendBinary(t *testing.T) {
	t.Parallel()

	s := newStorage(t, testRuleTextAll)
	idx := lookup.NewShortcutIndex()
	loadIndex(t, idx, s)

	data, err := idx.AppendBinary(nil)
	require.NoError(t, err)

	require.True(t, t.Run("valid_cbor", func(t *testing.T) {
		var v any
		err = cbor.Unmarshal(data, &v)
		require.NoError(t, err)
	}))

	require.True(t, t.Run("same_results", func(t *testing.T) {
		origStrg := newBaseFilterStorage(t)
		orig := lookup.NewDomainIndex()
		loadIndex(t, orig, origStrg)

		var origData []byte
		origData, err = orig.AppendBinary(nil)
		require.NoError(t, err)

		decoded := lookup.NewDomainIndex()
		err = decoded.UnmarshalBinary(origData)
		require.NoError(t, err)

		assertSameDomainResults(t, orig, decoded)
	}))
}

// assertSameDomainResults uses the AdGuard Base Filter to check if the two
// domain indexes issue the same results.
func assertSameDomainResults(tb testing.TB, original, decoded *lookup.DomainIndex) {
	tb.Helper()

	requests := parseAdGuardBaseDomainRequests(tb)
	for _, r := range requests {
		origRes := make([]filterlist.StorageID, 0, 2)
		origRes = original.AppendMatching(origRes, r)

		decRes := make([]filterlist.StorageID, 0, 2)
		decRes = decoded.AppendMatching(decRes, r)

		assert.Equalf(tb, origRes, decRes, "request: %+v\n", r)
	}
}

// domainRegexp is the regular expression used to extract a matching rule from a
// simple AdBlock rule with the domain modifier.
var domainRegexp = regexp.MustCompilePOSIX(`^\|\|([^^]+)\^\$domain=([^,|]+).*$`)

// parseAdGuardBaseDomainRequests returns filtering requests that can be used
// for matching the AdGuard Base Filter rules with the domain modifier.
func parseAdGuardBaseDomainRequests(tb testing.TB) (requests []*rules.Request) {
	tb.Helper()

	sc := bufio.NewScanner(bytes.NewReader(testBaseFilterData))
	for sc.Scan() {
		line := sc.Text()
		matches := domainRegexp.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		require.Len(tb, matches, 3)

		hostname := matches[1]
		require.NotEmpty(tb, hostname)

		srcHostname := matches[2]
		require.NotEmpty(tb, srcHostname)

		if srcHostname[0] == '~' {
			srcHostname = srcHostname[1:] + ".other.domain.example"
		}

		requests = append(requests, &rules.Request{
			Hostname:       hostname,
			SourceHostname: srcHostname,
		})
	}

	require.NoError(tb, sc.Err())
	require.NotEmpty(tb, requests)

	return requests
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
	s := newBaseFilterStorage(b)
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

	assert.Equal(b, filterlist.NewStorageID(2, 6605416), gotIDs[0])
	assert.Equal(b, filterlist.NewStorageID(2, 6615547), gotIDs[1])

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/urlfilter/internal/lookup
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkDomainIndex_AppendMatching_baseFilter-16     	11390737	     105.9 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkDomainIndex_init_baseFilter(b *testing.B) {
	s := newBaseFilterStorage(b)
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

	data, err := idx.AppendBinary(nil)
	require.NoError(b, err)

	var v any
	err = cbor.Unmarshal(data, &v)
	require.NoError(b, err)

	require.True(b, b.Run("unmarshal_binary", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			idx.Reset()
			err = idx.UnmarshalBinary(data)
		}

		require.NoError(b, err)
	}))

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/urlfilter/internal/lookup
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkDomainIndex_init_baseFilter/add-16  	      15	  74477428 ns/op	59832396 B/op	  763929 allocs/op
	//	BenchmarkDomainIndex_init_baseFilter/unmarshal_binary-16         	    1180	   1004302 ns/op	  725402 B/op	   13025 allocs/op
}
