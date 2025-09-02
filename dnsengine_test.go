package urlfilter

import (
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/internal/ufnet"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDNSEnginePriority(t *testing.T) {
	rulesText := `@@||example.org^
127.0.0.1  example.org
`

	ruleStorage := newTestRuleStorage(t, 1, rulesText)
	dnsEngine := NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	r, ok := dnsEngine.Match("example.org")
	require.True(t, ok)
	require.NotNil(t, r)
	require.NotNil(t, r.NetworkRule)

	assert.True(t, r.NetworkRule.Whitelist)
	assert.Nil(t, r.HostRulesV4)
	assert.Nil(t, r.HostRulesV6)
}

func TestDNSEngineMatchHostname(t *testing.T) {
	rulesText := `||example.org^
||example2.org/*
||example3.org|
0.0.0.0 v4.com
127.0.0.1 v4.com
:: v6.com
127.0.0.1 v4and6.com
127.0.0.2 v4and6.com
::1 v4and6.com
::2 v4and6.com
`
	ruleStorage := newTestRuleStorage(t, 1, rulesText)
	dnsEngine := NewDNSEngine(ruleStorage)
	require.NotNil(t, dnsEngine)

	r, ok := dnsEngine.Match("example.org")
	require.True(t, ok)

	assert.NotNil(t, r.NetworkRule)

	r, ok = dnsEngine.Match("example2.org")
	require.True(t, ok)

	assert.NotNil(t, r.NetworkRule)

	r, ok = dnsEngine.Match("example3.org")
	require.True(t, ok)

	assert.NotNil(t, r.NetworkRule)

	r, ok = dnsEngine.Match("v4.com")
	require.True(t, ok)
	require.Len(t, r.HostRulesV4, 2)

	assert.Equal(t, r.HostRulesV4[0].IP, netip.MustParseAddr("0.0.0.0"))
	assert.Equal(t, r.HostRulesV4[1].IP, testIPv4)

	r, ok = dnsEngine.Match("v6.com")
	require.True(t, ok)
	require.Len(t, r.HostRulesV6, 1)

	assert.Equal(t, r.HostRulesV6[0].IP, netip.MustParseAddr("::"))

	r, ok = dnsEngine.Match("v4and6.com")
	require.True(t, ok)
	require.Len(t, r.HostRulesV4, 2)
	require.Len(t, r.HostRulesV6, 2)

	assert.Equal(t, r.HostRulesV4[0].IP, testIPv4)
	assert.Equal(t, r.HostRulesV4[1].IP, anotherIPv4)
	assert.Equal(t, r.HostRulesV6[0].IP, testIPv6)
	assert.Equal(t, r.HostRulesV6[1].IP, anotherIPv6)

	_, ok = dnsEngine.Match("example.net")
	assert.False(t, ok)
}

func TestHostLevelNetworkRuleWithProtocol(t *testing.T) {
	rulesText := "://example.org"
	ruleStorage := newTestRuleStorage(t, 1, rulesText)
	dnsEngine := NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	r, ok := dnsEngine.Match("example.org")
	assert.True(t, ok)
	assert.True(t, r.NetworkRule != nil)
}

func TestRegexp(t *testing.T) {
	text := "/^stats?\\./"
	ruleStorage := newTestRuleStorage(t, 1, text)
	dnsEngine := NewDNSEngine(ruleStorage)

	res, ok := dnsEngine.Match("stats.test.com")
	assert.True(t, ok && res.NetworkRule.Text() == text)

	text = "@@/^stats?\\./"
	ruleStorage = newTestRuleStorage(t, 1, "||stats.test.com^\n"+text)
	dnsEngine = NewDNSEngine(ruleStorage)

	res, ok = dnsEngine.Match("stats.test.com")
	assert.True(t, ok && res.NetworkRule.Text() == text && res.NetworkRule.Whitelist)
}

func TestMultipleIPPerHost(t *testing.T) {
	text := `1.1.1.1 example.org
2.2.2.2 example.org`
	ruleStorage := newTestRuleStorage(t, 1, text)
	dnsEngine := NewDNSEngine(ruleStorage)

	res, ok := dnsEngine.Match("example.org")
	require.True(t, ok)
	require.Equal(t, 2, len(res.HostRulesV4))
}

func TestClientTags(t *testing.T) {
	rulesText := `||host1^$ctag=pc|printer
||host1^
||host2^$ctag=pc|printer
||host2^$ctag=pc|printer|router
||host3^$ctag=~pc|~router
||host4^$ctag=~pc|router
||host5^$ctag=pc|printer
||host5^$ctag=pc|printer,badfilter
||host6^$ctag=pc|printer
||host6^$badfilter
||host7^$ctag=~pc
||host7^$ctag=~pc,badfilter
`
	ruleStorage := newTestRuleStorage(t, 1, rulesText)
	dnsEngine := NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	// global rule
	res, ok := dnsEngine.MatchRequest(&DNSRequest{Hostname: "host1", SortedClientTags: []string{"phone"}})
	assert.True(t, ok)
	assert.NotNil(t, res.NetworkRule)
	assert.Equal(t, "||host1^", res.NetworkRule.Text())

	// $ctag rule overrides global rule
	res, ok = dnsEngine.MatchRequest(&DNSRequest{Hostname: "host1", SortedClientTags: []string{"pc"}})
	assert.True(t, ok)
	assert.NotNil(t, res.NetworkRule)
	assert.Equal(t, "||host1^$ctag=pc|printer", res.NetworkRule.Text())

	// 1 tag matches
	res, ok = dnsEngine.MatchRequest(&DNSRequest{Hostname: "host2", SortedClientTags: []string{"phone", "printer"}})
	assert.True(t, ok)
	assert.NotNil(t, res.NetworkRule)
	assert.Equal(t, "||host2^$ctag=pc|printer", res.NetworkRule.Text())

	// tags don't match
	_, ok = dnsEngine.MatchRequest(&DNSRequest{Hostname: "host2", SortedClientTags: []string{"phone"}})
	assert.False(t, ok)

	// tags don't match
	_, ok = dnsEngine.MatchRequest(&DNSRequest{Hostname: "host2", SortedClientTags: []string{}})
	assert.False(t, ok)

	// 1 tag matches (exclusion)
	res, ok = dnsEngine.MatchRequest(&DNSRequest{Hostname: "host3", SortedClientTags: []string{"phone", "printer"}})
	assert.True(t, ok)
	assert.NotNil(t, res.NetworkRule)
	assert.Equal(t, "||host3^$ctag=~pc|~router", res.NetworkRule.Text())

	// 1 tag matches (exclusion)
	res, ok = dnsEngine.MatchRequest(&DNSRequest{Hostname: "host4", SortedClientTags: []string{"phone", "router"}})
	assert.True(t, ok)
	assert.NotNil(t, res.NetworkRule)
	assert.Equal(t, "||host4^$ctag=~pc|router", res.NetworkRule.Text())

	// tags don't match (exclusion)
	_, ok = dnsEngine.MatchRequest(&DNSRequest{Hostname: "host3", SortedClientTags: []string{"pc"}})
	assert.False(t, ok)

	// tags don't match (exclusion)
	_, ok = dnsEngine.MatchRequest(&DNSRequest{Hostname: "host4", SortedClientTags: []string{"pc", "router"}})
	assert.False(t, ok)

	// tags match but it's a $badfilter
	_, ok = dnsEngine.MatchRequest(&DNSRequest{Hostname: "host5", SortedClientTags: []string{"pc"}})
	assert.False(t, ok)

	// tags match and $badfilter rule disables global rule
	res, ok = dnsEngine.MatchRequest(&DNSRequest{Hostname: "host6", SortedClientTags: []string{"pc"}})
	assert.True(t, ok)
	assert.NotNil(t, res.NetworkRule)
	assert.Equal(t, "||host6^$ctag=pc|printer", res.NetworkRule.Text())

	// tags match (exclusion) but it's a $badfilter
	_, ok = dnsEngine.MatchRequest(&DNSRequest{Hostname: "host7", SortedClientTags: []string{"phone"}})
	assert.False(t, ok)
}

func TestClient(t *testing.T) {
	ruleTexts := []string{
		"||host0^$client=127.0.0.1",
		"||host1^$client=~127.0.0.1",
		"||host2^$client=2001::c0:ffee",
		"||host3^$client=~2001::c0:ffee",
		"||host4^$client=127.0.0.1/24",
		"||host5^$client=~127.0.0.1/24",
		"||host6^$client=2001::c0:ffee/120",
		"||host7^$client=~2001::c0:ffee/120",
		"||host8^$client='Frank\\'s laptop'",
		"||host9^$client=0.0.0.0",
		"||host10^$client=::",
	}
	ruleStorage := newTestRuleStorage(t, 1, strings.Join(ruleTexts, "\n"))
	dnsEngine := NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	testCases := []struct {
		req     *DNSRequest
		wantRes string
		name    string
	}{{
		req:     &DNSRequest{Hostname: "host0", ClientIP: testIPv4},
		wantRes: ruleTexts[0],
		name:    "match_ipv4",
	}, {
		req:     &DNSRequest{Hostname: "host0", ClientIP: anotherIPv4},
		wantRes: "",
		name:    "mismatch_ipv4",
	}, {
		req:     &DNSRequest{Hostname: "host1", ClientIP: testIPv4},
		wantRes: "",
		name:    "restricted_ipv4",
	}, {
		req:     &DNSRequest{Hostname: "host1", ClientIP: anotherIPv4},
		wantRes: ruleTexts[1],
		name:    "non_restricted_ipv4",
	}, {
		req:     &DNSRequest{Hostname: "host2", ClientIP: netip.MustParseAddr("2001::c0:ffee")},
		wantRes: ruleTexts[2],
		name:    "match_ipv6",
	}, {
		req:     &DNSRequest{Hostname: "host2", ClientIP: netip.MustParseAddr("2001::c0:ffef")},
		wantRes: "",
		name:    "mismatch_ipv6",
	}, {
		req:     &DNSRequest{Hostname: "host3", ClientIP: netip.MustParseAddr("2001::c0:ffee")},
		wantRes: "",
		name:    "restricted_ipv6",
	}, {
		req:     &DNSRequest{Hostname: "host3", ClientIP: netip.MustParseAddr("2001::c0:ffef")},
		wantRes: ruleTexts[3],
		name:    "non_restricted_ipv6",
	}, {
		req:     &DNSRequest{Hostname: "host4", ClientIP: netip.MustParseAddr("127.0.0.254")},
		wantRes: ruleTexts[4],
		name:    "match_ipv4_subnet",
	}, {
		req:     &DNSRequest{Hostname: "host4", ClientIP: netip.MustParseAddr("127.0.1.1")},
		wantRes: "",
		name:    "mismatch_ipv4_subnet",
	}, {
		req:     &DNSRequest{Hostname: "host5", ClientIP: netip.MustParseAddr("127.0.0.254")},
		wantRes: "",
		name:    "restricted_ipv4_subnet",
	}, {
		req:     &DNSRequest{Hostname: "host5", ClientIP: netip.MustParseAddr("127.0.1.1")},
		wantRes: ruleTexts[5],
		name:    "non_restricted_ipv4_subnet",
	}, {
		req:     &DNSRequest{Hostname: "host6", ClientIP: netip.MustParseAddr("2001::c0:ff07")},
		wantRes: ruleTexts[6],
		name:    "match_ipv6_subnet",
	}, {
		req:     &DNSRequest{Hostname: "host6", ClientIP: netip.MustParseAddr("2001::c0:feee")},
		wantRes: "",
		name:    "mismatch_ipv6_subnet",
	}, {
		req:     &DNSRequest{Hostname: "host7", ClientIP: netip.MustParseAddr("2001::c0:ff07")},
		wantRes: "",
		name:    "restricted_ipv6_subnet",
	}, {
		req:     &DNSRequest{Hostname: "host7", ClientIP: netip.MustParseAddr("2001::c0:feee")},
		wantRes: ruleTexts[7],
		name:    "non_restricted_ipv6_subnet",
	}, {
		req:     &DNSRequest{Hostname: "host8", ClientName: "Frank's laptop"},
		wantRes: ruleTexts[8],
		name:    "match_name",
	}, {
		req:     &DNSRequest{Hostname: "host8", ClientName: "Franks laptop"},
		wantRes: "",
		name:    "mismatch_name",
	}, {
		req:     &DNSRequest{Hostname: "host9", ClientIP: netip.IPv4Unspecified()},
		wantRes: ruleTexts[9],
		name:    "match_unspecified_ipv4",
	}, {
		req:     &DNSRequest{Hostname: "host9", ClientIP: testIPv4},
		wantRes: "",
		name:    "mismatch_unspecified_ipv4",
	}, {
		req:     &DNSRequest{Hostname: "host10"},
		wantRes: "",
		name:    "no_ipv4",
	}, {
		req:     &DNSRequest{Hostname: "host10", ClientIP: netip.IPv6Unspecified()},
		wantRes: ruleTexts[10],
		name:    "match_unspecified_ipv6",
	}, {
		req:     &DNSRequest{Hostname: "host10", ClientIP: testIPv6},
		wantRes: "",
		name:    "mismatch_unspecified_ipv6",
	}, {
		req:     &DNSRequest{Hostname: "host10"},
		wantRes: "",
		name:    "no_ipv6",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res, ok := dnsEngine.MatchRequest(tc.req)
			if tc.wantRes == "" {
				assert.False(t, ok)
			} else {
				assertMatchRuleText(t, tc.wantRes, res, ok)
			}
		})
	}
}

func TestBadfilterRules(t *testing.T) {
	rulesText := "||example.org^\n||example.org^$badfilter"
	ruleStorage := newTestRuleStorage(t, 1, rulesText)
	dnsEngine := NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	r, ok := dnsEngine.Match("example.org")
	assert.False(t, ok)
	assert.True(t, r.NetworkRule == nil && r.HostRulesV4 == nil && r.HostRulesV6 == nil)
}

func TestDNSEngine_MatchRequest_dnsType(t *testing.T) {
	const rulesText = `
||simple^$dnstype=AAAA
||simple_case^$dnstype=aaaa
||reverse^$dnstype=~AAAA
||multiple^$dnstype=A|AAAA
||multiple_reverse^$dnstype=~A|~AAAA
||multiple_different^$dnstype=~A|AAAA
||simple_client^$client=127.0.0.1,dnstype=AAAA
||priority^$client=127.0.0.1
||priority^$client=127.0.0.1,dnstype=AAAA
`

	ruleStorage := newTestRuleStorage(t, 1, rulesText)
	dnsEngine := NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	t.Run("simple", func(t *testing.T) {
		r := &DNSRequest{Hostname: "simple", DNSType: dns.TypeAAAA}
		_, ok := dnsEngine.MatchRequest(r)
		assert.True(t, ok)

		r.DNSType = dns.TypeA
		_, ok = dnsEngine.MatchRequest(r)
		assert.False(t, ok)
	})

	t.Run("simple_case", func(t *testing.T) {
		r := &DNSRequest{Hostname: "simple_case", DNSType: dns.TypeAAAA}
		_, ok := dnsEngine.MatchRequest(r)
		assert.True(t, ok)

		r.DNSType = dns.TypeA
		_, ok = dnsEngine.MatchRequest(r)
		assert.False(t, ok)
	})

	t.Run("reverse", func(t *testing.T) {
		r := &DNSRequest{Hostname: "reverse", DNSType: dns.TypeAAAA}
		_, ok := dnsEngine.MatchRequest(r)
		assert.False(t, ok)

		r.DNSType = dns.TypeA
		_, ok = dnsEngine.MatchRequest(r)
		assert.True(t, ok)
	})

	t.Run("multiple", func(t *testing.T) {
		r := &DNSRequest{Hostname: "multiple", DNSType: dns.TypeAAAA}
		_, ok := dnsEngine.MatchRequest(r)
		assert.True(t, ok)

		r.DNSType = dns.TypeA
		_, ok = dnsEngine.MatchRequest(r)
		assert.True(t, ok)

		r.DNSType = dns.TypeCNAME
		_, ok = dnsEngine.MatchRequest(r)
		assert.False(t, ok)
	})

	t.Run("multiple_reverse", func(t *testing.T) {
		r := &DNSRequest{
			Hostname: "multiple_reverse",
			DNSType:  dns.TypeAAAA,
		}

		_, ok := dnsEngine.MatchRequest(r)
		assert.False(t, ok)

		r.DNSType = dns.TypeA
		_, ok = dnsEngine.MatchRequest(r)
		assert.False(t, ok)

		r.DNSType = dns.TypeCNAME
		_, ok = dnsEngine.MatchRequest(r)
		assert.True(t, ok)
	})

	t.Run("multiple_different", func(t *testing.T) {
		// Should be the same as simple.
		r := &DNSRequest{
			Hostname: "multiple_different",
			DNSType:  dns.TypeAAAA,
		}

		_, ok := dnsEngine.MatchRequest(r)
		assert.True(t, ok)

		r.DNSType = dns.TypeA
		_, ok = dnsEngine.MatchRequest(r)
		assert.False(t, ok)

		r.DNSType = dns.TypeCNAME
		_, ok = dnsEngine.MatchRequest(r)
		assert.False(t, ok)
	})

	t.Run("simple_client", func(t *testing.T) {
		r := &DNSRequest{
			Hostname: "simple_client",
			DNSType:  dns.TypeAAAA,
			ClientIP: testIPv4,
		}

		_, ok := dnsEngine.MatchRequest(r)
		assert.True(t, ok)

		r = &DNSRequest{
			Hostname: "simple_client",
			DNSType:  dns.TypeAAAA,
			ClientIP: anotherIPv4,
		}
		_, ok = dnsEngine.MatchRequest(r)
		assert.False(t, ok)

		r = &DNSRequest{
			Hostname: "simple_client",
			DNSType:  dns.TypeA,
			ClientIP: testIPv4,
		}
		_, ok = dnsEngine.MatchRequest(r)
		assert.False(t, ok)
	})

	t.Run("priority", func(t *testing.T) {
		r := &DNSRequest{
			Hostname: "priority",
			DNSType:  dns.TypeAAAA,
			ClientIP: testIPv4,
		}

		res, ok := dnsEngine.MatchRequest(r)
		assert.True(t, ok)
		assert.Contains(t, res.NetworkRule.Text(), "dnstype=")

		r = &DNSRequest{
			Hostname: "priority",
			DNSType:  dns.TypeA,
			ClientIP: testIPv4,
		}
		res, ok = dnsEngine.MatchRequest(r)
		assert.True(t, ok)
		assert.NotContains(t, res.NetworkRule.Text(), "dnstype=")
	})
}

func TestSlash(t *testing.T) {
	ruleStorage := newTestRuleStorage(t, 1, "/$client=127.0.0.1")
	dnsEngine := NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	r, ok := dnsEngine.Match("example.org")
	assert.False(t, ok)
	assert.True(t, r.NetworkRule == nil && r.HostRulesV4 == nil && r.HostRulesV6 == nil)
}

func assertMatchRuleText(t *testing.T, rulesText string, rules *DNSResult, ok bool) {
	assert.True(t, ok)
	if ok {
		assert.NotNil(t, rules.NetworkRule)
		assert.Equal(t, rulesText, rules.NetworkRule.Text())
	}
}

// BenchmarkDNSEngine_heapAlloc is a benchmark used to measure changes in the
// heap-allocated memory during typical operation of a DNS engine.  It reports
// the following additional metrics:
//   - initial_heap_bytes: the size of allocated heap objects before doing
//     anything.
//   - heap_after_loading_bytes: the size of allocated heap objects after
//     compiling rule lists.
//   - heap_after_matching_bytes: the size of allocated heap objects after
//     matching a few requests with the engine.
//
// NOTE:  The precise values of the aforementioned metrics may vary from run to
// run.  Benchmark with --benchtime no less than 10s and --count no less than 10
// to get a better picture of the real changes in performance.
func BenchmarkDNSEngine_heapAlloc(b *testing.B) {
	ruleStorage := newRuleStorage(b)
	testutil.CleanupAndRequireSuccess(b, ruleStorage.Close)

	testHostnames := loadHostnames(b)

	b.ReportAllocs()
	for b.Loop() {
		runtime.GC()

		b.ReportMetric(heapAlloc(b), "initial_heap_bytes")

		dnsEngine := NewDNSEngine(ruleStorage)

		b.ReportMetric(heapAlloc(b), "heap_after_loading_bytes")

		req := &DNSRequest{}
		res := &DNSResult{}

		var ok bool
		for _, reqHostname := range testHostnames {
			req.Hostname = reqHostname
			res.Reset()

			ok = dnsEngine.MatchRequestInto(req, res)
		}

		require.True(b, ok)

		b.ReportMetric(heapAlloc(b), "heap_after_matching_bytes")
	}

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/urlfilter
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkDNSEngine_heapAlloc-16    	      62	 188650046 ns/op	  23325288 heap_after_loading_bytes	  24206128 heap_after_matching_bytes	  11498392 initial_heap_bytes	54128187 B/op	  874266 allocs/op
}

// heapAlloc is a helper that returns the current heap-allocated bytes as
// counted by the runtime.
func heapAlloc(tb testing.TB) (heap float64) {
	tb.Helper()

	m := &runtime.MemStats{}
	runtime.ReadMemStats(m)

	return float64(m.HeapAlloc)
}

func BenchmarkDNSEngine_Match(b *testing.B) {
	testHostnames := loadHostnames(b)

	ruleStorage := newRuleStorage(b)
	testutil.CleanupAndRequireSuccess(b, ruleStorage.Close)

	dnsEngine := NewDNSEngine(ruleStorage)

	var r *DNSResult
	var match bool

	b.ReportAllocs()
	for b.Loop() {
		for _, reqHostname := range testHostnames {
			r, match = dnsEngine.Match(reqHostname)
		}
	}

	assert.NotNil(b, r)
	assert.True(b, match)

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/urlfilter
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkDNSEngine_Match-16    	     207	  57062240 ns/op	 3237680 B/op	   69208 allocs/op
}

func BenchmarkDNSEngine_MatchRequestInto(b *testing.B) {
	testHostnames := loadHostnames(b)

	ruleStorage := newRuleStorage(b)
	testutil.CleanupAndRequireSuccess(b, ruleStorage.Close)

	dnsEngine := NewDNSEngine(ruleStorage)

	var match bool
	req := &DNSRequest{}
	res := &DNSResult{}

	b.ReportAllocs()
	for b.Loop() {
		for _, reqHostname := range testHostnames {
			req.Hostname = reqHostname
			res.Reset()

			match = dnsEngine.MatchRequestInto(req, res)
		}
	}

	assert.True(b, match)

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/urlfilter
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkDNSEngine_MatchRequestInto-16    	     240	  49861837 ns/op	  856973 B/op	   28219 allocs/op
}

func FuzzDNSEngine_Match(f *testing.F) {
	for _, seed := range []string{
		"",
		" ",
		"\n",
		"1",
		"127.0.0.1",
		"example.test",
	} {
		f.Add(seed)
	}

	rulesText := `||example.test^
||example2.test/*
0.0.0.0 v4.com
127.0.0.1 v4.com
:: v6.com
::1 v4and6.com
`

	lists := []filterlist.Interface{
		filterlist.NewString(&filterlist.StringConfig{
			RulesText: rulesText,
			ID:        1,
		}),
	}

	ruleStorage, err := filterlist.NewRuleStorage(lists)
	require.NoError(f, err)

	testutil.CleanupAndRequireSuccess(f, ruleStorage.Close)

	dnsEngine := NewDNSEngine(ruleStorage)

	f.Fuzz(func(t *testing.T, hostname string) {
		assert.NotPanics(t, func() {
			_, _ = dnsEngine.Match(hostname)
		}, hostname)
	})
}

// ruleListFromPath returns a rule list loaded from a file.
func ruleListFromPath(tb testing.TB, path string, id int) (l *filterlist.Bytes) {
	tb.Helper()

	rulesText, err := os.ReadFile(path)
	require.NoError(tb, err)

	return filterlist.NewBytes(&filterlist.BytesConfig{
		RulesText:      rulesText,
		ID:             id,
		IgnoreCosmetic: true,
	})
}

const (
	networkFilterPath = testResourcesDir + "/adguard_sdn_filter.txt"
	hostsPath         = testResourcesDir + "/hosts"
)

// newRuleStorage returns new properly initialized rules storage with test data.
func newRuleStorage(tb testing.TB) (ruleStorage *filterlist.RuleStorage) {
	tb.Helper()

	filterRuleList := ruleListFromPath(tb, networkFilterPath, 1)
	hostsRuleList := ruleListFromPath(tb, hostsPath, 2)

	ruleLists := []filterlist.Interface{
		filterRuleList,
		hostsRuleList,
	}

	ruleStorage, err := filterlist.NewRuleStorage(ruleLists)
	require.NoError(tb, err)

	return ruleStorage
}

// loadHostnames returns a slice of test hostnames.
func loadHostnames(t *testing.B) (hostnames []string) {
	t.Helper()

	for _, req := range loadRequests(t) {
		h := ufnet.ExtractHostname(req.URL)
		if h != "" {
			hostnames = append(hostnames, h)
		}
	}

	return hostnames
}
