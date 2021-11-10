package urlfilter

import (
	"net"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/filterutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	networkFilterPath = testResourcesDir + "/adguard_sdn_filter.txt"
	hostsPath         = testResourcesDir + "/hosts"
)

func TestBenchDNSEngine(t *testing.T) {
	debug.SetGCPercent(10)

	filterRuleList, err := filterlist.NewFileRuleList(1, networkFilterPath, true)
	if err != nil {
		t.Fatalf("cannot read %s", networkFilterPath)
	}

	hostsRuleList, err := filterlist.NewFileRuleList(2, hostsPath, true)
	if err != nil {
		t.Fatalf("cannot read %s", hostsPath)
	}

	ruleLists := []filterlist.RuleList{
		filterRuleList,
		hostsRuleList,
	}
	ruleStorage, err := filterlist.NewRuleStorage(ruleLists)
	if err != nil {
		t.Fatalf("cannot create rule storage: %s", err)
	}
	defer func() { assert.Nil(t, ruleStorage.Close()) }()

	testRequests := loadRequests(t)
	assert.True(t, len(testRequests) > 0)
	var testHostnames []string
	for _, req := range testRequests {
		h := filterutil.ExtractHostname(req.URL)
		if h != "" {
			testHostnames = append(testHostnames, h)
		}
	}

	startHeap, startRSS := alloc(t)
	t.Logf(
		"Allocated before loading rules (heap/RSS, kiB): %d/%d",
		startHeap,
		startRSS,
	)

	startParse := time.Now()
	dnsEngine := NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	t.Logf("Elapsed on parsing rules: %v", time.Since(startParse))
	t.Logf("Rules count - %v", dnsEngine.RulesCount)

	loadHeap, loadRSS := alloc(t)
	t.Logf(
		"Allocated after loading rules (heap/RSS, kiB): %d/%d (%d/%d diff)",
		loadHeap,
		loadRSS,
		loadHeap-startHeap,
		loadRSS-startRSS,
	)

	totalMatches := 0
	totalElapsed := time.Duration(0)
	minElapsedMatch := time.Hour
	maxElapsedMatch := time.Duration(0)

	for i, reqHostname := range testHostnames {
		if i != 0 && i%10000 == 0 {
			t.Logf("Processed %d requests", i)
		}

		startMatch := time.Now()
		res, found := dnsEngine.Match(reqHostname)
		elapsedMatch := time.Since(startMatch)
		totalElapsed += elapsedMatch
		if elapsedMatch > maxElapsedMatch {
			maxElapsedMatch = elapsedMatch
		}
		if elapsedMatch < minElapsedMatch {
			minElapsedMatch = elapsedMatch
		}

		if found {
			if res.NetworkRule != nil {
				if !res.NetworkRule.Whitelist {
					totalMatches++
				}
			} else if res.HostRulesV4 != nil || res.HostRulesV6 != nil {
				totalMatches++
			}
		}
	}

	t.Logf("Total matches: %d", totalMatches)
	t.Logf("Total elapsed: %v", totalElapsed)
	t.Logf("Average per request: %v", time.Duration(int64(totalElapsed)/int64(len(testHostnames))))
	t.Logf("Max per request: %v", maxElapsedMatch)
	t.Logf("Min per request: %v", minElapsedMatch)
	t.Logf("Storage cache length: %d", ruleStorage.GetCacheSize())

	matchHeap, matchRSS := alloc(t)
	t.Logf(
		"Allocated after matching (heap/RSS, kiB): %d/%d (%d/%d diff)",
		matchHeap,
		matchRSS,
		matchHeap-loadHeap,
		matchRSS-loadRSS,
	)
}

func TestDNSEnginePriority(t *testing.T) {
	rulesText := `@@||example.org^
127.0.0.1  example.org
`

	ruleStorage := newTestRuleStorage(t, 1, rulesText)
	dnsEngine := NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	r, ok := dnsEngine.Match("example.org")
	assert.True(t, ok)
	assert.NotNil(t, r)
	assert.NotNil(t, r.NetworkRule)
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

	assert.Equal(t, r.HostRulesV4[0].IP, net.ParseIP("0.0.0.0"))
	assert.Equal(t, r.HostRulesV4[1].IP, net.ParseIP("127.0.0.1"))

	r, ok = dnsEngine.Match("v6.com")
	require.True(t, ok)
	require.Len(t, r.HostRulesV6, 1)

	assert.Equal(t, r.HostRulesV6[0].IP, net.ParseIP("::"))

	r, ok = dnsEngine.Match("v4and6.com")
	require.True(t, ok)
	require.Len(t, r.HostRulesV4, 2)
	require.Len(t, r.HostRulesV6, 2)

	assert.Equal(t, r.HostRulesV4[0].IP, net.ParseIP("127.0.0.1"))
	assert.Equal(t, r.HostRulesV4[1].IP, net.ParseIP("127.0.0.2"))
	assert.Equal(t, r.HostRulesV6[0].IP, net.ParseIP("::1"))
	assert.Equal(t, r.HostRulesV6[1].IP, net.ParseIP("::2"))

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
	res, ok := dnsEngine.MatchRequest(DNSRequest{Hostname: "host1", SortedClientTags: []string{"phone"}})
	assert.True(t, ok)
	assert.NotNil(t, res.NetworkRule)
	assert.Equal(t, "||host1^", res.NetworkRule.Text())

	// $ctag rule overrides global rule
	res, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host1", SortedClientTags: []string{"pc"}})
	assert.True(t, ok)
	assert.NotNil(t, res.NetworkRule)
	assert.Equal(t, "||host1^$ctag=pc|printer", res.NetworkRule.Text())

	// 1 tag matches
	res, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host2", SortedClientTags: []string{"phone", "printer"}})
	assert.True(t, ok)
	assert.NotNil(t, res.NetworkRule)
	assert.Equal(t, "||host2^$ctag=pc|printer", res.NetworkRule.Text())

	// tags don't match
	res, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host2", SortedClientTags: []string{"phone"}})
	assert.False(t, ok)

	// tags don't match
	res, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host2", SortedClientTags: []string{}})
	assert.False(t, ok)

	// 1 tag matches (exclusion)
	res, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host3", SortedClientTags: []string{"phone", "printer"}})
	assert.True(t, ok)
	assert.NotNil(t, res.NetworkRule)
	assert.Equal(t, "||host3^$ctag=~pc|~router", res.NetworkRule.Text())

	// 1 tag matches (exclusion)
	res, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host4", SortedClientTags: []string{"phone", "router"}})
	assert.True(t, ok)
	assert.NotNil(t, res.NetworkRule)
	assert.Equal(t, "||host4^$ctag=~pc|router", res.NetworkRule.Text())

	// tags don't match (exclusion)
	res, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host3", SortedClientTags: []string{"pc"}})
	assert.False(t, ok)

	// tags don't match (exclusion)
	res, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host4", SortedClientTags: []string{"pc", "router"}})
	assert.False(t, ok)

	// tags match but it's a $badfilter
	res, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host5", SortedClientTags: []string{"pc"}})
	assert.False(t, ok)

	// tags match and $badfilter rule disables global rule
	res, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host6", SortedClientTags: []string{"pc"}})
	assert.True(t, ok)
	assert.NotNil(t, res.NetworkRule)
	assert.Equal(t, "||host6^$ctag=pc|printer", res.NetworkRule.Text())

	// tags match (exclusion) but it's a $badfilter
	res, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host7", SortedClientTags: []string{"phone"}})
	assert.False(t, ok)
}

func TestClient(t *testing.T) {
	rulesText := []string{
		"||host0^$client=127.0.0.1",
		"||host1^$client=~127.0.0.1",
		"||host2^$client=2001::c0:ffee",
		"||host3^$client=~2001::c0:ffee",
		"||host4^$client=127.0.0.1/24",
		"||host5^$client=~127.0.0.1/24",
		"||host6^$client=2001::c0:ffee/120",
		"||host7^$client=~2001::c0:ffee/120",
		"||host8^$client='Frank\\'s laptop'",
	}
	ruleStorage := newTestRuleStorage(t, 1, strings.Join(rulesText, "\n"))
	dnsEngine := NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	// match client IPv4
	res, ok := dnsEngine.MatchRequest(DNSRequest{Hostname: "host0", ClientIP: "127.0.0.1"})
	assertMatchRuleText(t, rulesText[0], res, ok)

	// not match client IPv4
	_, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host0", ClientIP: "127.0.0.2"})
	assert.False(t, ok)

	// restricted client IPv4
	_, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host1", ClientIP: "127.0.0.1"})
	assert.False(t, ok)

	// non-restricted client IPv4
	res, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host1", ClientIP: "127.0.0.2"})
	assertMatchRuleText(t, rulesText[1], res, ok)

	// match client IPv6
	res, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host2", ClientIP: "2001::c0:ffee"})
	assertMatchRuleText(t, rulesText[2], res, ok)

	// not match client IPv6
	_, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host2", ClientIP: "2001::c0:ffef"})
	assert.False(t, ok)

	// restricted client IPv6
	_, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host3", ClientIP: "2001::c0:ffee"})
	assert.False(t, ok)

	// non-restricted client IPv6
	res, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host3", ClientIP: "2001::c0:ffef"})
	assertMatchRuleText(t, rulesText[3], res, ok)

	// match network IPv4
	res, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host4", ClientIP: "127.0.0.254"})
	assertMatchRuleText(t, rulesText[4], res, ok)

	// not match network IPv4
	_, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host4", ClientIP: "127.0.1.1"})
	assert.False(t, ok)

	// restricted network IPv4
	_, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host5", ClientIP: "127.0.0.254"})
	assert.False(t, ok)

	// non-restricted network IPv4
	res, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host5", ClientIP: "127.0.1.1"})
	assertMatchRuleText(t, rulesText[5], res, ok)

	// match network IPv6
	res, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host6", ClientIP: "2001::c0:ff07"})
	assertMatchRuleText(t, rulesText[6], res, ok)

	// not match network IPv6
	_, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host6", ClientIP: "2001::c0:feee"})
	assert.False(t, ok)

	// restricted network IPv6
	_, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host7", ClientIP: "2001::c0:ff07"})
	assert.False(t, ok)

	// non-restricted network IPv6
	res, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host7", ClientIP: "2001::c0:feee"})
	assertMatchRuleText(t, rulesText[7], res, ok)

	// match client name
	res, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host8", ClientName: "Frank's laptop"})
	assertMatchRuleText(t, rulesText[8], res, ok)

	// not match client name
	_, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host8", ClientName: "Franks laptop"})
	assert.False(t, ok)
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
		r := DNSRequest{Hostname: "simple", DNSType: dns.TypeAAAA}
		_, ok := dnsEngine.MatchRequest(r)
		assert.True(t, ok)

		r.DNSType = dns.TypeA
		_, ok = dnsEngine.MatchRequest(r)
		assert.False(t, ok)
	})

	t.Run("simple_case", func(t *testing.T) {
		r := DNSRequest{Hostname: "simple_case", DNSType: dns.TypeAAAA}
		_, ok := dnsEngine.MatchRequest(r)
		assert.True(t, ok)

		r.DNSType = dns.TypeA
		_, ok = dnsEngine.MatchRequest(r)
		assert.False(t, ok)
	})

	t.Run("reverse", func(t *testing.T) {
		r := DNSRequest{Hostname: "reverse", DNSType: dns.TypeAAAA}
		_, ok := dnsEngine.MatchRequest(r)
		assert.False(t, ok)

		r.DNSType = dns.TypeA
		_, ok = dnsEngine.MatchRequest(r)
		assert.True(t, ok)
	})

	t.Run("multiple", func(t *testing.T) {
		r := DNSRequest{Hostname: "multiple", DNSType: dns.TypeAAAA}
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
		r := DNSRequest{
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
		r := DNSRequest{
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
		r := DNSRequest{
			Hostname: "simple_client",
			DNSType:  dns.TypeAAAA,
			ClientIP: "127.0.0.1",
		}

		_, ok := dnsEngine.MatchRequest(r)
		assert.True(t, ok)

		r = DNSRequest{
			Hostname: "simple_client",
			DNSType:  dns.TypeAAAA,
			ClientIP: "127.0.0.2",
		}
		_, ok = dnsEngine.MatchRequest(r)
		assert.False(t, ok)

		r = DNSRequest{
			Hostname: "simple_client",
			DNSType:  dns.TypeA,
			ClientIP: "127.0.0.1",
		}
		_, ok = dnsEngine.MatchRequest(r)
		assert.False(t, ok)
	})

	t.Run("priority", func(t *testing.T) {
		r := DNSRequest{
			Hostname: "priority",
			DNSType:  dns.TypeAAAA,
			ClientIP: "127.0.0.1",
		}

		res, ok := dnsEngine.MatchRequest(r)
		assert.True(t, ok)
		assert.Contains(t, res.NetworkRule.Text(), "dnstype=")

		r = DNSRequest{
			Hostname: "priority",
			DNSType:  dns.TypeA,
			ClientIP: "127.0.0.1",
		}
		res, ok = dnsEngine.MatchRequest(r)
		assert.True(t, ok)
		assert.NotContains(t, res.NetworkRule.Text(), "dnstype=")
	})
}

func assertMatchRuleText(t *testing.T, rulesText string, rules *DNSResult, ok bool) {
	assert.True(t, ok)
	if ok {
		assert.NotNil(t, rules.NetworkRule)
		assert.Equal(t, rulesText, rules.NetworkRule.Text())
	}
}
