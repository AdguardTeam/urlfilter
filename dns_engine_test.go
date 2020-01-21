package urlfilter

import (
	"runtime/debug"
	"testing"
	"time"

	"github.com/AdguardTeam/urlfilter/filterlist"

	"github.com/AdguardTeam/urlfilter/rules"

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
		matchingRules, found := dnsEngine.Match(reqHostname, nil)
		elapsedMatch := time.Since(startMatch)
		totalElapsed += elapsedMatch
		if elapsedMatch > maxElapsedMatch {
			maxElapsedMatch = elapsedMatch
		}
		if elapsedMatch < minElapsedMatch {
			minElapsedMatch = elapsedMatch
		}

		if found {
			switch v := matchingRules[0].(type) {
			case *rules.HostRule:
				totalMatches++
			case *rules.NetworkRule:
				if !v.Whitelist {
					totalMatches++
				}
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

func TestDNSEngineMatchHostname(t *testing.T) {
	rulesText := "||example.org^\n||example2.org/*\n0.0.0.0 example.com"
	ruleStorage := newTestRuleStorage(t, 1, rulesText)
	dnsEngine := NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	r, ok := dnsEngine.Match("example.org", nil)
	assert.True(t, ok)
	assert.True(t, len(r) == 1)

	_, ok = r[0].(*rules.NetworkRule)
	assert.True(t, ok)

	r, ok = dnsEngine.Match("example2.org", nil)
	assert.True(t, ok)
	assert.True(t, len(r) == 1)
	_, ok = r[0].(*rules.NetworkRule)
	assert.True(t, ok)

	r, ok = dnsEngine.Match("example.com", nil)
	assert.True(t, ok)
	assert.True(t, len(r) == 1)

	_, ok = r[0].(*rules.HostRule)
	assert.True(t, ok)

	_, ok = dnsEngine.Match("example.net", nil)
	assert.False(t, ok)
}

func TestDNSEngineMatchIP6(t *testing.T) {
	rulesText := "192.168.1.1 example.org\n2000:: example.org"
	ruleStorage := newTestRuleStorage(t, 1, rulesText)
	dnsEngine := NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	r, ok := dnsEngine.Match("example.org", nil)
	assert.True(t, ok)
	assert.True(t, len(r) == 2)
}

func TestHostLevelNetworkRuleWithProtocol(t *testing.T) {
	rulesText := "://example.org"
	ruleStorage := newTestRuleStorage(t, 1, rulesText)
	dnsEngine := NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	r, ok := dnsEngine.Match("example.org", nil)
	assert.True(t, ok)
	assert.True(t, len(r) == 1)
}

func TestRegexp(t *testing.T) {
	text := "/^stats?\\./"
	ruleStorage := newTestRuleStorage(t, 1, text)
	dnsEngine := NewDNSEngine(ruleStorage)

	matchingRules, ok := dnsEngine.Match("stats.test.com", nil)
	assert.True(t, ok && matchingRules[0].Text() == text)

	text = "@@/^stats?\\./"
	ruleStorage = newTestRuleStorage(t, 1, "||stats.test.com^\n"+text)
	dnsEngine = NewDNSEngine(ruleStorage)

	matchingRules, ok = dnsEngine.Match("stats.test.com", nil)
	nr := matchingRules[0].(*rules.NetworkRule)
	assert.True(t, ok && matchingRules[0].Text() == text && nr.Whitelist)
}

func TestClientTags(t *testing.T) {
	rulesText := `||host1^$ctag=pc|printer
||host2^$ctag=pc|printer
||host2^$ctag=pc|printer|router
||host3^$ctag=~pc|~router
||host4^$ctag=~pc|router
||host1^
||host1^$ctag=pc|printer
`
	ruleStorage := newTestRuleStorage(t, 1, rulesText)
	dnsEngine := NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	// global rule
	rules, ok := dnsEngine.MatchWithClientTags("host1", []string{"phone"})
	assert.True(t, ok)
	assert.True(t, len(rules) == 1)
	assert.True(t, rules[0].Text() == "||host1^")

	// 1 tag matches
	rules, ok = dnsEngine.MatchWithClientTags("host2", []string{"phone", "router"})
	assert.True(t, ok)
	assert.True(t, len(rules) == 1)
	assert.True(t, rules[0].Text() == "||host2^$ctag=pc|printer|router")

	// tags don't match
	rules, ok = dnsEngine.MatchWithClientTags("host2", []string{"phone"})
	assert.True(t, !ok)

	// tags don't match
	rules, ok = dnsEngine.MatchWithClientTags("host2", []string{})
	assert.True(t, !ok)

	// 1 tag matches (exclusion)
	rules, ok = dnsEngine.MatchWithClientTags("host3", []string{"phone", "printer"})
	assert.True(t, ok)
	assert.True(t, len(rules) == 1)
	assert.True(t, rules[0].Text() == "||host3^$ctag=~pc|~router")

	// 1 tag matches (exclusion)
	rules, ok = dnsEngine.MatchWithClientTags("host4", []string{"phone", "router"})
	assert.True(t, ok)
	assert.True(t, len(rules) == 1)
	assert.True(t, rules[0].Text() == "||host4^$ctag=~pc|router")

	// tags don't match (exclusion)
	rules, ok = dnsEngine.MatchWithClientTags("host3", []string{"pc"})
	assert.True(t, !ok)

	// tags don't match (exclusion)
	rules, ok = dnsEngine.MatchWithClientTags("host4", []string{"pc", "router"})
	assert.True(t, !ok)
}

func TestBadfilterRules(t *testing.T) {
	rulesText := "||example.org^\n||example.org^$badfilter"
	ruleStorage := newTestRuleStorage(t, 1, rulesText)
	dnsEngine := NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	r, ok := dnsEngine.Match("example.org", nil)
	assert.False(t, ok)
	assert.Nil(t, r)
}
