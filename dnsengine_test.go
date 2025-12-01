package urlfilter_test

import (
	"bufio"
	"net/netip"
	"os"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/internal/uftest"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDNSEnginePriority(t *testing.T) {
	rulesText := `@@||example.org^
127.0.0.1  example.org
`

	ruleStorage := newTestRuleStorage(t, uftest.ListID1, rulesText)
	dnsEngine := urlfilter.NewDNSEngine(ruleStorage)
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
	ruleStorage := newTestRuleStorage(t, uftest.ListID1, rulesText)
	dnsEngine := urlfilter.NewDNSEngine(ruleStorage)
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
	ruleStorage := newTestRuleStorage(t, uftest.ListID1, rulesText)
	dnsEngine := urlfilter.NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	r, ok := dnsEngine.Match("example.org")
	assert.True(t, ok)
	assert.True(t, r.NetworkRule != nil)
}

func TestRegexp(t *testing.T) {
	text := "/^stats?\\./"
	ruleStorage := newTestRuleStorage(t, uftest.ListID1, text)
	dnsEngine := urlfilter.NewDNSEngine(ruleStorage)

	res, ok := dnsEngine.Match("stats.test.com")
	assert.True(t, ok && res.NetworkRule.Text() == text)

	text = "@@/^stats?\\./"
	ruleStorage = newTestRuleStorage(t, uftest.ListID1, "||stats.test.com^\n"+text)
	dnsEngine = urlfilter.NewDNSEngine(ruleStorage)

	res, ok = dnsEngine.Match("stats.test.com")
	assert.True(t, ok && res.NetworkRule.Text() == text && res.NetworkRule.Whitelist)
}

func TestMultipleIPPerHost(t *testing.T) {
	text := `1.1.1.1 example.org
2.2.2.2 example.org`
	ruleStorage := newTestRuleStorage(t, uftest.ListID1, text)
	dnsEngine := urlfilter.NewDNSEngine(ruleStorage)

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
	ruleStorage := newTestRuleStorage(t, uftest.ListID1, rulesText)
	dnsEngine := urlfilter.NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	// global rule
	res, ok := dnsEngine.MatchRequest(&urlfilter.DNSRequest{
		Hostname:   "host1",
		ClientTags: container.NewSortedSliceSet("phone"),
	})
	assert.True(t, ok)
	assert.NotNil(t, res.NetworkRule)
	assert.Equal(t, "||host1^", res.NetworkRule.Text())

	// $ctag rule overrides global rule
	res, ok = dnsEngine.MatchRequest(&urlfilter.DNSRequest{
		Hostname:   "host1",
		ClientTags: container.NewSortedSliceSet("pc"),
	})
	assert.True(t, ok)
	assert.NotNil(t, res.NetworkRule)
	assert.Equal(t, "||host1^$ctag=pc|printer", res.NetworkRule.Text())

	// 1 tag matches
	res, ok = dnsEngine.MatchRequest(&urlfilter.DNSRequest{
		Hostname:   "host2",
		ClientTags: container.NewSortedSliceSet("phone", "printer"),
	})
	assert.True(t, ok)
	assert.NotNil(t, res.NetworkRule)
	assert.Equal(t, "||host2^$ctag=pc|printer", res.NetworkRule.Text())

	// tags don't match
	_, ok = dnsEngine.MatchRequest(&urlfilter.DNSRequest{
		Hostname:   "host2",
		ClientTags: container.NewSortedSliceSet("phone"),
	})
	assert.False(t, ok)

	// tags don't match
	_, ok = dnsEngine.MatchRequest(&urlfilter.DNSRequest{
		Hostname:   "host2",
		ClientTags: container.NewSortedSliceSet[string](),
	})
	assert.False(t, ok)

	// 1 tag matches (exclusion)
	res, ok = dnsEngine.MatchRequest(&urlfilter.DNSRequest{
		Hostname:   "host3",
		ClientTags: container.NewSortedSliceSet("phone", "printer"),
	})
	assert.True(t, ok)
	assert.NotNil(t, res.NetworkRule)
	assert.Equal(t, "||host3^$ctag=~pc|~router", res.NetworkRule.Text())

	// 1 tag matches (exclusion)
	res, ok = dnsEngine.MatchRequest(&urlfilter.DNSRequest{
		Hostname:   "host4",
		ClientTags: container.NewSortedSliceSet("phone", "router"),
	})
	assert.True(t, ok)
	assert.NotNil(t, res.NetworkRule)
	assert.Equal(t, "||host4^$ctag=~pc|router", res.NetworkRule.Text())

	// tags don't match (exclusion)
	_, ok = dnsEngine.MatchRequest(&urlfilter.DNSRequest{
		Hostname:   "host3",
		ClientTags: container.NewSortedSliceSet("pc"),
	})
	assert.False(t, ok)

	// tags don't match (exclusion)
	_, ok = dnsEngine.MatchRequest(&urlfilter.DNSRequest{
		Hostname:   "host4",
		ClientTags: container.NewSortedSliceSet("pc", "router"),
	})
	assert.False(t, ok)

	// tags match but it's a $badfilter
	_, ok = dnsEngine.MatchRequest(&urlfilter.DNSRequest{
		Hostname:   "host5",
		ClientTags: container.NewSortedSliceSet("pc"),
	})
	assert.False(t, ok)

	// tags match and $badfilter rule disables global rule
	res, ok = dnsEngine.MatchRequest(&urlfilter.DNSRequest{
		Hostname:   "host6",
		ClientTags: container.NewSortedSliceSet("pc"),
	})
	assert.True(t, ok)
	assert.NotNil(t, res.NetworkRule)
	assert.Equal(t, "||host6^$ctag=pc|printer", res.NetworkRule.Text())

	// tags match (exclusion) but it's a $badfilter
	_, ok = dnsEngine.MatchRequest(&urlfilter.DNSRequest{
		Hostname:   "host7",
		ClientTags: container.NewSortedSliceSet("phone"),
	})
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
	ruleStorage := newTestRuleStorage(t, uftest.ListID1, strings.Join(ruleTexts, "\n"))
	dnsEngine := urlfilter.NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	testCases := []struct {
		req     *urlfilter.DNSRequest
		wantRes string
		name    string
	}{{
		req:     &urlfilter.DNSRequest{Hostname: "host0", ClientIP: testIPv4},
		wantRes: ruleTexts[0],
		name:    "match_ipv4",
	}, {
		req:     &urlfilter.DNSRequest{Hostname: "host0", ClientIP: anotherIPv4},
		wantRes: "",
		name:    "mismatch_ipv4",
	}, {
		req:     &urlfilter.DNSRequest{Hostname: "host1", ClientIP: testIPv4},
		wantRes: "",
		name:    "restricted_ipv4",
	}, {
		req:     &urlfilter.DNSRequest{Hostname: "host1", ClientIP: anotherIPv4},
		wantRes: ruleTexts[1],
		name:    "non_restricted_ipv4",
	}, {
		req:     &urlfilter.DNSRequest{Hostname: "host2", ClientIP: netip.MustParseAddr("2001::c0:ffee")},
		wantRes: ruleTexts[2],
		name:    "match_ipv6",
	}, {
		req:     &urlfilter.DNSRequest{Hostname: "host2", ClientIP: netip.MustParseAddr("2001::c0:ffef")},
		wantRes: "",
		name:    "mismatch_ipv6",
	}, {
		req:     &urlfilter.DNSRequest{Hostname: "host3", ClientIP: netip.MustParseAddr("2001::c0:ffee")},
		wantRes: "",
		name:    "restricted_ipv6",
	}, {
		req:     &urlfilter.DNSRequest{Hostname: "host3", ClientIP: netip.MustParseAddr("2001::c0:ffef")},
		wantRes: ruleTexts[3],
		name:    "non_restricted_ipv6",
	}, {
		req:     &urlfilter.DNSRequest{Hostname: "host4", ClientIP: netip.MustParseAddr("127.0.0.254")},
		wantRes: ruleTexts[4],
		name:    "match_ipv4_subnet",
	}, {
		req:     &urlfilter.DNSRequest{Hostname: "host4", ClientIP: netip.MustParseAddr("127.0.1.1")},
		wantRes: "",
		name:    "mismatch_ipv4_subnet",
	}, {
		req:     &urlfilter.DNSRequest{Hostname: "host5", ClientIP: netip.MustParseAddr("127.0.0.254")},
		wantRes: "",
		name:    "restricted_ipv4_subnet",
	}, {
		req:     &urlfilter.DNSRequest{Hostname: "host5", ClientIP: netip.MustParseAddr("127.0.1.1")},
		wantRes: ruleTexts[5],
		name:    "non_restricted_ipv4_subnet",
	}, {
		req:     &urlfilter.DNSRequest{Hostname: "host6", ClientIP: netip.MustParseAddr("2001::c0:ff07")},
		wantRes: ruleTexts[6],
		name:    "match_ipv6_subnet",
	}, {
		req:     &urlfilter.DNSRequest{Hostname: "host6", ClientIP: netip.MustParseAddr("2001::c0:feee")},
		wantRes: "",
		name:    "mismatch_ipv6_subnet",
	}, {
		req:     &urlfilter.DNSRequest{Hostname: "host7", ClientIP: netip.MustParseAddr("2001::c0:ff07")},
		wantRes: "",
		name:    "restricted_ipv6_subnet",
	}, {
		req:     &urlfilter.DNSRequest{Hostname: "host7", ClientIP: netip.MustParseAddr("2001::c0:feee")},
		wantRes: ruleTexts[7],
		name:    "non_restricted_ipv6_subnet",
	}, {
		req: &urlfilter.DNSRequest{
			Hostname:          "host8",
			ClientIdentifiers: container.NewSortedSliceSet("Frank's laptop"),
		},
		wantRes: ruleTexts[8],
		name:    "match_name",
	}, {
		req: &urlfilter.DNSRequest{
			Hostname:          "host8",
			ClientIdentifiers: container.NewSortedSliceSet("Franks laptop"),
		},
		wantRes: "",
		name:    "mismatch_name",
	}, {
		req:     &urlfilter.DNSRequest{Hostname: "host9", ClientIP: netip.IPv4Unspecified()},
		wantRes: ruleTexts[9],
		name:    "match_unspecified_ipv4",
	}, {
		req:     &urlfilter.DNSRequest{Hostname: "host9", ClientIP: testIPv4},
		wantRes: "",
		name:    "mismatch_unspecified_ipv4",
	}, {
		req:     &urlfilter.DNSRequest{Hostname: "host10"},
		wantRes: "",
		name:    "no_ipv4",
	}, {
		req:     &urlfilter.DNSRequest{Hostname: "host10", ClientIP: netip.IPv6Unspecified()},
		wantRes: ruleTexts[10],
		name:    "match_unspecified_ipv6",
	}, {
		req:     &urlfilter.DNSRequest{Hostname: "host10", ClientIP: testIPv6},
		wantRes: "",
		name:    "mismatch_unspecified_ipv6",
	}, {
		req:     &urlfilter.DNSRequest{Hostname: "host10"},
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
	ruleStorage := newTestRuleStorage(t, uftest.ListID1, rulesText)
	dnsEngine := urlfilter.NewDNSEngine(ruleStorage)
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

	ruleStorage := newTestRuleStorage(t, uftest.ListID1, rulesText)
	dnsEngine := urlfilter.NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	t.Run("simple", func(t *testing.T) {
		r := &urlfilter.DNSRequest{Hostname: "simple", DNSType: dns.TypeAAAA}
		_, ok := dnsEngine.MatchRequest(r)
		assert.True(t, ok)

		r.DNSType = dns.TypeA
		_, ok = dnsEngine.MatchRequest(r)
		assert.False(t, ok)
	})

	t.Run("simple_case", func(t *testing.T) {
		r := &urlfilter.DNSRequest{Hostname: "simple_case", DNSType: dns.TypeAAAA}
		_, ok := dnsEngine.MatchRequest(r)
		assert.True(t, ok)

		r.DNSType = dns.TypeA
		_, ok = dnsEngine.MatchRequest(r)
		assert.False(t, ok)
	})

	t.Run("reverse", func(t *testing.T) {
		r := &urlfilter.DNSRequest{Hostname: "reverse", DNSType: dns.TypeAAAA}
		_, ok := dnsEngine.MatchRequest(r)
		assert.False(t, ok)

		r.DNSType = dns.TypeA
		_, ok = dnsEngine.MatchRequest(r)
		assert.True(t, ok)
	})

	t.Run("multiple", func(t *testing.T) {
		r := &urlfilter.DNSRequest{Hostname: "multiple", DNSType: dns.TypeAAAA}
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
		r := &urlfilter.DNSRequest{
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
		r := &urlfilter.DNSRequest{
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
		r := &urlfilter.DNSRequest{
			Hostname: "simple_client",
			DNSType:  dns.TypeAAAA,
			ClientIP: testIPv4,
		}

		_, ok := dnsEngine.MatchRequest(r)
		assert.True(t, ok)

		r = &urlfilter.DNSRequest{
			Hostname: "simple_client",
			DNSType:  dns.TypeAAAA,
			ClientIP: anotherIPv4,
		}
		_, ok = dnsEngine.MatchRequest(r)
		assert.False(t, ok)

		r = &urlfilter.DNSRequest{
			Hostname: "simple_client",
			DNSType:  dns.TypeA,
			ClientIP: testIPv4,
		}
		_, ok = dnsEngine.MatchRequest(r)
		assert.False(t, ok)
	})

	t.Run("priority", func(t *testing.T) {
		r := &urlfilter.DNSRequest{
			Hostname: "priority",
			DNSType:  dns.TypeAAAA,
			ClientIP: testIPv4,
		}

		res, ok := dnsEngine.MatchRequest(r)
		assert.True(t, ok)
		assert.Contains(t, res.NetworkRule.Text(), "dnstype=")

		r = &urlfilter.DNSRequest{
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
	ruleStorage := newTestRuleStorage(t, uftest.ListID1, "/$client=127.0.0.1")
	dnsEngine := urlfilter.NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	r, ok := dnsEngine.Match("example.org")
	assert.False(t, ok)
	assert.True(t, r.NetworkRule == nil && r.HostRulesV4 == nil && r.HostRulesV6 == nil)
}

func assertMatchRuleText(t *testing.T, rulesText string, rules *urlfilter.DNSResult, ok bool) {
	assert.True(t, ok)
	if ok {
		assert.NotNil(t, rules.NetworkRule)
		assert.Equal(t, rulesText, rules.NetworkRule.Text())
	}
}

// BenchmarkDNSEngine_heapAlloc is a benchmark used to measure changes in the
// heap-allocated memory during typical operation of a DNS engine.  It reports
// the following additional metrics:
//   - heap_initial_bytes/op: the average size of allocated heap objects before
//     doing anything.
//   - heap_after_compilation_bytes/op: the average size of allocated heap
//     objects after compiling rule lists.
//   - heap_after_matching_bytes/op: the average size of allocated heap objects
//     after matching a few requests with the engine.
//
// NOTE:  The precise values of the aforementioned metrics may vary from run to
// run.  Benchmark with --benchtime no less than 10s and --count no less than 11
// to get a better picture of the real changes in performance and discard the
// first warmup run.
func BenchmarkDNSEngine_heapAlloc(b *testing.B) {
	s := newDNSRuleStorage(b)
	matchingHostnames := parseAdGuardSDNHostnames(b)

	nonMatchingHostnames := []string{"non-matching.example"}

	benchCases := []struct {
		name           string
		wantAllMatched require.BoolAssertionFunc
		hostnames      []string
		numIter        int
	}{{
		name:           "1_matching",
		wantAllMatched: require.True,
		hostnames:      matchingHostnames,
		numIter:        1,
	}, {
		name:           "10_matching",
		wantAllMatched: require.True,
		hostnames:      matchingHostnames,
		numIter:        10,
	}, {
		name:           "100_matching",
		wantAllMatched: require.True,
		hostnames:      matchingHostnames,
		numIter:        100,
	}, {
		name:           "1_non_matching",
		wantAllMatched: require.False,
		hostnames:      nonMatchingHostnames,
		numIter:        1,
	}, {
		name:           "10_non_matching",
		wantAllMatched: require.False,
		hostnames:      nonMatchingHostnames,
		numIter:        10,
	}, {
		name:           "100_non_matching",
		wantAllMatched: require.False,
		hostnames:      nonMatchingHostnames,
		numIter:        100,
	}}

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			m := &dnsEngineMeasurement{}

			allMatched := false
			b.ReportAllocs()
			for b.Loop() {
				allMatched = m.run(s, bc.hostnames, bc.numIter)
			}

			bc.wantAllMatched(b, allMatched)

			n := float64(b.N)

			b.ReportMetric(m.initialSum/n, "heap_initial_bytes/op")
			b.ReportMetric(m.afterCompilationSum/n, "heap_after_compilation_bytes/op")
			b.ReportMetric(m.afterMatchingSum/n, "heap_after_matching_bytes/op")
		})
	}

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/urlfilter
	//	cpu: Apple M3
	//	BenchmarkDNSEngine_heapAlloc/1_matching-8         	       8	 192417896 ns/op	 171684650 heap_after_compilation_bytes/op	 174154105 heap_after_matching_bytes/op	 140625226 heap_initial_bytes/op	33518451 B/op	  533789 allocs/op
	//	BenchmarkDNSEngine_heapAlloc/10_matching-8        	       2	 1429245396 ns/op	 171551868 heap_after_compilation_bytes/op	 195331496 heap_after_matching_bytes/op	 140615404 heap_initial_bytes/op	54716140 B/op	  1277712 allocs/op
	//	BenchmarkDNSEngine_heapAlloc/100_matching-8       	       1	 12506500041 ns/op	 171609656 heap_after_compilation_bytes/op	 281924200 heap_after_matching_bytes/op	 140574824 heap_initial_bytes/op	267684776 B/op	  8716885 allocs/op
	//	BenchmarkDNSEngine_heapAlloc/1_non_matching-8     	      58	  31100568 ns/op	 171625776 heap_after_compilation_bytes/op	 171629768 heap_after_matching_bytes/op	 140584160 heap_initial_bytes/op	31045626 B/op	  450720 allocs/op
	//	BenchmarkDNSEngine_heapAlloc/10_non_matching-8    	      58	  31121919 ns/op	 171625554 heap_after_compilation_bytes/op	 171629834 heap_after_matching_bytes/op	 140589035 heap_initial_bytes/op	31040805 B/op	  450729 allocs/op
	//	BenchmarkDNSEngine_heapAlloc/100_non_matching-8   	      58	  30898313 ns/op	 171626982 heap_after_compilation_bytes/op	 171634142 heap_after_matching_bytes/op	 140585366 heap_initial_bytes/op	31048792 B/op	  450819 allocs/op
}

// DNS filter paths for tests.
const (
	networkFilterPath = testResourcesDir + "/adguard_sdn_filter.txt"
	hostsPath         = testResourcesDir + "/hosts"
)

// newDNSRuleStorage returns new properly initialized rules storage with test
// data from the AdGuard SDN filter.  It also adds its Close method to tb's
// cleanup.
func newDNSRuleStorage(tb testing.TB) (ruleStorage *filterlist.RuleStorage) {
	tb.Helper()

	filterRuleList := ruleListFromPath(tb, networkFilterPath, uftest.ListID1)
	hostsRuleList := ruleListFromPath(tb, hostsPath, uftest.ListID2)
	ruleStorage, err := filterlist.NewRuleStorage([]filterlist.Interface{
		filterRuleList,
		hostsRuleList,
	})
	require.NoError(tb, err)

	testutil.CleanupAndRequireSuccess(tb, ruleStorage.Close)

	return ruleStorage
}

// adBlockRegexp is the regular expression used to extract a matching hostname
// from a simple AdBlock rule.
var adBlockRegexp = regexp.MustCompilePOSIX(`^\|\|([^^]+)\^$`)

// parseAdGuardSDNHostnames returns hostnames that can be used for matching the
// AdGuard Simplified Domain Names (SDN) filter.
func parseAdGuardSDNHostnames(tb testing.TB) (hostnames []string) {
	tb.Helper()

	// Firstly, extract some hostnames that can be easily checked against from
	// the SDN filter.
	netFile, err := os.Open(networkFilterPath)
	require.NoError(tb, err)
	// Do not use [testutil.CleanupAndRequireSuccess], because the file should
	// be closed by the end of this function.
	defer func() { require.NoError(tb, netFile.Close()) }()

	sc := bufio.NewScanner(netFile)
	for sc.Scan() {
		line := sc.Text()
		matches := adBlockRegexp.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		require.Len(tb, matches, 2)
		require.NotEmpty(tb, matches[1])

		hostnames = append(hostnames, matches[1])
	}

	require.NoError(tb, sc.Err())

	// Secondly, extract some hostnames from the hosts file.
	hostsFile, err := os.Open(hostsPath)
	require.NoError(tb, err)
	defer func() { require.NoError(tb, hostsFile.Close()) }()

	sc = bufio.NewScanner(hostsFile)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}

		_, hostname, ok := strings.Cut(line, " ")
		if ok && netutil.IsValidHostname(hostname) {
			hostnames = append(hostnames, hostname)
		}
	}

	require.NoError(tb, sc.Err())
	require.NotEmpty(tb, hostnames)

	return hostnames
}

// dnsEngineMeasurement emulates a life cycle of a DNS filtering engine.
type dnsEngineMeasurement struct {
	initialSum          float64
	afterCompilationSum float64
	afterMatchingSum    float64
}

// run performs a DNS engine life cycle.  s must not be nil.  numIter should be
// greater than zero.
func (m *dnsEngineMeasurement) run(
	s *filterlist.RuleStorage,
	hostnames []string,
	numIter int,
) (allMatched bool) {
	runtime.GC()

	m.initialSum += heapAlloc()

	dnsEngine := urlfilter.NewDNSEngine(s)

	m.afterCompilationSum += heapAlloc()

	req := &urlfilter.DNSRequest{}
	res := &urlfilter.DNSResult{}

	allMatched = true
	for range numIter {
		for _, reqHostname := range hostnames {
			req.Hostname = reqHostname
			res.Reset()

			ok := dnsEngine.MatchRequestInto(req, res)
			allMatched = allMatched && ok
		}
	}

	m.afterMatchingSum += heapAlloc()

	return allMatched
}

func BenchmarkDNSEngine_Match(b *testing.B) {
	reqHostnames := uftest.RequestHostnames(b)

	ruleStorage := newDNSRuleStorage(b)
	dnsEngine := urlfilter.NewDNSEngine(ruleStorage)

	// Warmup to fill the pools.
	var r *urlfilter.DNSResult
	var match bool
	for _, reqHostname := range reqHostnames {
		r, match = dnsEngine.Match(reqHostname)
	}

	b.ReportAllocs()
	for b.Loop() {
		for _, reqHostname := range reqHostnames {
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
	//	BenchmarkDNSEngine_Match-16    	      20	  61072490 ns/op	 3193156 B/op	   68918 allocs/op
}

func BenchmarkDNSEngine_MatchRequestInto(b *testing.B) {
	reqHostnames := uftest.RequestHostnames(b)

	ruleStorage := newDNSRuleStorage(b)
	dnsEngine := urlfilter.NewDNSEngine(ruleStorage)

	var match bool
	req := &urlfilter.DNSRequest{}
	res := &urlfilter.DNSResult{}

	// Warmup to fill the structs and the pools.
	for _, reqHostname := range reqHostnames {
		req.Hostname = reqHostname
		res.Reset()

		match = dnsEngine.MatchRequestInto(req, res)
	}

	b.ReportAllocs()
	for b.Loop() {
		for _, reqHostname := range reqHostnames {
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
	//	BenchmarkDNSEngine_MatchRequestInto-16    	      22	  50762008 ns/op	  814592 B/op	   27969 allocs/op
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

	ruleStorage := newTestRuleStorage(f, uftest.ListID1, rulesText)
	dnsEngine := urlfilter.NewDNSEngine(ruleStorage)

	f.Fuzz(func(t *testing.T, hostname string) {
		assert.NotPanics(t, func() {
			_, _ = dnsEngine.Match(hostname)
		}, hostname)
	})
}

// ruleListFromPath returns a rule list loaded from a file.
func ruleListFromPath(tb testing.TB, path string, id rules.ListID) (l *filterlist.Bytes) {
	tb.Helper()

	rulesText, err := os.ReadFile(path)
	require.NoError(tb, err)

	return filterlist.NewBytes(&filterlist.BytesConfig{
		RulesText:      rulesText,
		ID:             id,
		IgnoreCosmetic: true,
	})
}
