package lookup_test

import (
	"bufio"
	"bytes"
	"net/url"
	"regexp"
	"testing"

	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/internal/lookup"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/fxamacker/cbor/v2"
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

func TestShortcutIndex_AppendBinary(t *testing.T) {
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
		orig := lookup.NewShortcutIndex()
		loadIndex(t, orig, origStrg)

		var origData []byte
		origData, err = orig.AppendBinary(nil)
		require.NoError(t, err)

		decoded := lookup.NewShortcutIndex()
		err = decoded.UnmarshalBinary(origData)
		require.NoError(t, err)

		assertSameShortcutResults(t, orig, decoded)
	}))
}

// assertSameShortcutResults uses the AdGuard Base Filter to check if the two
// shortcut indexes issue the same results.
func assertSameShortcutResults(tb testing.TB, original, decoded *lookup.ShortcutIndex) {
	tb.Helper()

	requests := parseAdGuardBaseShortcutRequests(tb)
	for _, r := range requests {
		origRes := make([]filterlist.StorageID, 0, 2)
		origRes = original.AppendMatching(origRes, r)

		decRes := make([]filterlist.StorageID, 0, 2)
		decRes = decoded.AppendMatching(decRes, r)

		assert.Equalf(tb, origRes, decRes, "request: %+v\n", r)
	}
}

// shortcutRegexp is the regular expression used to extract a matching rule from
// a simple AdBlock rule of sufficient length.
var shortcutRegexp = regexp.MustCompilePOSIX(`^\|\|([^^]{5,})\^`)

// parseAdGuardBaseShortcutRequests returns filtering requests that can be used
// for matching the AdGuard Base Filter rules.
func parseAdGuardBaseShortcutRequests(tb testing.TB) (requests []*rules.Request) {
	tb.Helper()

	sc := bufio.NewScanner(bytes.NewReader(testBaseFilterData))
	for sc.Scan() {
		line := sc.Text()
		matches := shortcutRegexp.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		require.Len(tb, matches, 2)

		hostname := matches[1]
		require.NotEmpty(tb, hostname)

		r := &rules.Request{
			URL: &url.URL{
				Scheme: urlutil.SchemeHTTP,
			},
		}
		rules.FillRequestForHostname(r, hostname)

		requests = append(requests, r)
	}

	require.NoError(tb, sc.Err())
	require.NotEmpty(tb, requests)

	return requests
}

func TestShortcutIndex_AppendMatching(t *testing.T) {
	t.Parallel()

	s := newStorage(t, testRuleTextAll)
	idx := lookup.NewShortcutIndex()
	loadIndex(t, idx, s)

	testCases := []struct {
		url    *url.URL
		name   string
		wantID filterlist.StorageID
	}{{
		name:   "no_match",
		url:    testURLNoMatch,
		wantID: filterlist.StorageID{},
	}, {
		name:   "match",
		url:    testURLWithDomain,
		wantID: filterlist.NewStorageID(1, 0),
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := rules.NewRequest(tc.url, tc.url, rules.TypeOther)
			assertMatch(t, idx, r, tc.wantID)
		})
	}
}

func BenchmarkShortcutIndex_AppendMatching(b *testing.B) {
	s := newStorage(b, testRuleTextAll)
	idx := lookup.NewShortcutIndex()
	loadIndex(b, idx, s)

	r := rules.NewRequest(testURLWithDomain, testURLWithDomain, rules.TypeOther)

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
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/urlfilter/internal/lookup
	//	cpu: Apple M1 Pro
	//	BenchmarkShortcutIndex_AppendMatching-8   	 6955702	       166.2 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkShortcutIndex_AppendMatching_baseFilter(b *testing.B) {
	s := newBaseFilterStorage(b)
	idx := lookup.NewShortcutIndex()
	loadIndex(b, idx, s)

	r := rules.NewRequest(testURLBaseFilterDomain, testURLBaseFilterDomain, rules.TypeOther)

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
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/urlfilter/internal/lookup
	//	cpu: Apple M1 Pro
	//	BenchmarkShortcutIndex_AppendMatching_baseFilter-8   	 1482379	       810.8 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkShortcutIndex_init_baseFilter(b *testing.B) {
	s := newBaseFilterStorage(b)
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
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/urlfilter/internal/lookup
	//	cpu: Apple M1 Pro
	//	BenchmarkShortcutIndex_init_baseFilter/add-8         	      18	  63896690 ns/op	60612069 B/op	  820547 allocs/op
	//	BenchmarkShortcutIndex_init_baseFilter/unmarshal_binary-8         	     211	   5597618 ns/op	 7743849 B/op	  132933 allocs/op
}
