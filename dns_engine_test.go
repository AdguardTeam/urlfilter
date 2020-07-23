package urlfilter

import (
	"net"
	"runtime/debug"
	"testing"
	"time"

	"github.com/AdguardTeam/urlfilter/filterlist"

	"github.com/AdguardTeam/urlfilter/filterutil"

	"github.com/AdguardTeam/golibs/log"
	"github.com/stretchr/testify/assert"
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
	defer ruleStorage.Close()

	testRequests := loadRequests(t)
	assert.True(t, len(testRequests) > 0)
	var testHostnames []string
	for _, req := range testRequests {
		h := filterutil.ExtractHostname(req.URL)
		if h != "" {
			testHostnames = append(testHostnames, h)
		}
	}

	start := getRSS()
	log.Printf("RSS before loading rules - %d kB", start/1024)

	startParse := time.Now()
	dnsEngine := NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	log.Printf("Elapsed on parsing rules: %v", time.Since(startParse))
	log.Printf("Rules count - %v", dnsEngine.RulesCount)

	afterLoad := getRSS()
	log.Printf("RSS after loading rules - %d kB (%d kB diff)", afterLoad/1024, (afterLoad-start)/1024)

	totalMatches := 0
	totalElapsed := time.Duration(0)
	minElapsedMatch := time.Hour
	maxElapsedMatch := time.Duration(0)

	for i, reqHostname := range testHostnames {
		if i != 0 && i%10000 == 0 {
			log.Printf("Processed %d requests", i)
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

	log.Printf("Total matches: %d", totalMatches)
	log.Printf("Total elapsed: %v", totalElapsed)
	log.Printf("Average per request: %v", time.Duration(int64(totalElapsed)/int64(len(testHostnames))))
	log.Printf("Max per request: %v", maxElapsedMatch)
	log.Printf("Min per request: %v", minElapsedMatch)
	log.Printf("Storage cache length: %d", ruleStorage.GetCacheSize())

	afterMatch := getRSS()
	log.Printf("RSS after matching - %d kB (%d kB diff)\n", afterMatch/1024, (afterMatch-afterLoad)/1024)
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
	assert.NotNil(t, dnsEngine)

	r, ok := dnsEngine.Match("example.org")
	assert.True(t, ok)
	assert.True(t, r.NetworkRule != nil)

	r, ok = dnsEngine.Match("example2.org")
	assert.True(t, ok)
	assert.True(t, r.NetworkRule != nil)

	r, ok = dnsEngine.Match("v4.com")
	assert.True(t, ok)
	assert.True(t, len(r.HostRulesV4) == 2)
	assert.True(t, r.HostRulesV4[0].IP.Equal(net.ParseIP("0.0.0.0")))
	assert.True(t, r.HostRulesV4[1].IP.Equal(net.ParseIP("127.0.0.1")))

	r, ok = dnsEngine.Match("v6.com")
	assert.True(t, ok)
	assert.True(t, len(r.HostRulesV6) == 1)
	assert.True(t, r.HostRulesV6[0].IP.Equal(net.ParseIP("::")))

	r, ok = dnsEngine.Match("v4and6.com")
	assert.True(t, ok)
	assert.True(t, len(r.HostRulesV4) == 2)
	assert.True(t, len(r.HostRulesV6) == 2)
	assert.True(t, r.HostRulesV4[0].IP.Equal(net.ParseIP("127.0.0.1")))
	assert.True(t, r.HostRulesV4[1].IP.Equal(net.ParseIP("127.0.0.2")))
	assert.True(t, r.HostRulesV6[0].IP.Equal(net.ParseIP("::1")))
	assert.True(t, r.HostRulesV6[1].IP.Equal(net.ParseIP("::2")))

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
	assert.True(t, res.NetworkRule.Text() == text && res.NetworkRule.Whitelist)
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
	rules, ok := dnsEngine.MatchRequest(DNSRequest{Hostname: "host1", SortedClientTags: []string{"phone"}})
	assert.True(t, ok)
	assert.NotNil(t, rules.NetworkRule)
	assert.Equal(t, "||host1^", rules.NetworkRule.Text())

	// $ctag rule overrides global rule
	rules, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host1", SortedClientTags: []string{"pc"}})
	assert.True(t, ok)
	assert.NotNil(t, rules.NetworkRule)
	assert.Equal(t, "||host1^$ctag=pc|printer", rules.NetworkRule.Text())

	// 1 tag matches
	rules, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host2", SortedClientTags: []string{"phone", "printer"}})
	assert.True(t, ok)
	assert.NotNil(t, rules.NetworkRule)
	assert.Equal(t, "||host2^$ctag=pc|printer", rules.NetworkRule.Text())

	// tags don't match
	rules, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host2", SortedClientTags: []string{"phone"}})
	assert.False(t, ok)

	// tags don't match
	rules, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host2", SortedClientTags: []string{}})
	assert.False(t, ok)

	// 1 tag matches (exclusion)
	rules, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host3", SortedClientTags: []string{"phone", "printer"}})
	assert.True(t, ok)
	assert.NotNil(t, rules.NetworkRule)
	assert.Equal(t, "||host3^$ctag=~pc|~router", rules.NetworkRule.Text())

	// 1 tag matches (exclusion)
	rules, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host4", SortedClientTags: []string{"phone", "router"}})
	assert.True(t, ok)
	assert.NotNil(t, rules.NetworkRule)
	assert.Equal(t, "||host4^$ctag=~pc|router", rules.NetworkRule.Text())

	// tags don't match (exclusion)
	rules, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host3", SortedClientTags: []string{"pc"}})
	assert.False(t, ok)

	// tags don't match (exclusion)
	rules, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host4", SortedClientTags: []string{"pc", "router"}})
	assert.False(t, ok)

	// tags match but it's a $badfilter
	rules, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host5", SortedClientTags: []string{"pc"}})
	assert.False(t, ok)

	// tags match and $badfilter rule disables global rule
	rules, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host6", SortedClientTags: []string{"pc"}})
	assert.True(t, ok)
	assert.NotNil(t, rules.NetworkRule)
	assert.Equal(t, "||host6^$ctag=pc|printer", rules.NetworkRule.Text())

	// tags match (exclusion) but it's a $badfilter
	rules, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host7", SortedClientTags: []string{"phone"}})
	assert.False(t, ok)
}

func TestClient(t *testing.T) {
	rulesText := `||host1^$client=127.0.0.1
||host2^$client=~127.0.0.1
||host3^$client='Frank\'s laptop'`
	ruleStorage := newTestRuleStorage(t, 1, rulesText)
	dnsEngine := NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	// match client IP
	rules, ok := dnsEngine.MatchRequest(DNSRequest{Hostname: "host1", ClientIP: "127.0.0.1"})
	assert.True(t, ok)
	assert.NotNil(t, rules.NetworkRule)
	assert.Equal(t, "||host1^$client=127.0.0.1", rules.NetworkRule.Text())

	// not match client IP
	rules, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host1", ClientIP: "127.0.0.2"})
	assert.False(t, ok)

	// restricted client IP
	rules, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host2", ClientIP: "127.0.0.1"})
	assert.False(t, ok)

	// non-restricted client IP
	rules, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host2", ClientIP: "127.0.0.2"})
	assert.NotNil(t, rules.NetworkRule)
	assert.Equal(t, "||host2^$client=~127.0.0.1", rules.NetworkRule.Text())

	// match client name
	rules, ok = dnsEngine.MatchRequest(DNSRequest{Hostname: "host3", ClientName: "Frank's laptop"})
	assert.NotNil(t, rules.NetworkRule)
	assert.Equal(t, "||host3^$client='Frank\\'s laptop'", rules.NetworkRule.Text())
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
