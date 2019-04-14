package urlfilter

import (
	"io/ioutil"
	"log"
	"runtime/debug"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	networkFilterPath = testResourcesDir + "/adguard_sdn_filter.txt"
	hostsPath         = testResourcesDir + "/hosts"
)

func TestBenchDNSEngine(t *testing.T) {
	debug.SetGCPercent(10)

	filterBytes, err := ioutil.ReadFile(networkFilterPath)
	if err != nil {
		t.Fatalf("cannot read %s", networkFilterPath)
	}

	hostsBytes, err := ioutil.ReadFile(hostsPath)
	if err != nil {
		t.Fatalf("cannot read %s", hostsPath)
	}

	filterLists := map[int]string{
		1: string(filterBytes), // (6652 kB diff in-memory / 5560 kB diff with file storage)
		2: string(hostsBytes),  // (9988 kB diff in-memory / 6480 kB diff with file storage)
	}

	testRequests := loadRequests(t)
	assert.True(t, len(testRequests) > 0)
	var testHostnames []string
	for _, req := range testRequests {
		h := extractHostname(req.URL)
		if h != "" {
			testHostnames = append(testHostnames, h)
		}
	}

	start := getRSS()
	log.Printf("RSS before loading rules - %d kB", start/1024)

	ruleStorage, err := NewRuleStorage("test/temp.db")
	if err != nil {
		t.Fatalf("cannot initialize rule storage: %s", err)
	}
	defer ruleStorage.Close()

	startParse := time.Now()
	dnsEngine := ParseDNSEngine(filterLists, ruleStorage)
	assert.NotNil(t, dnsEngine)

	log.Printf("Elapsed on parsing rules: %v", time.Since(startParse))
	log.Printf("Filters size - %d kB", len(filterBytes)/1024)
	log.Printf("Hosts size - %d kB", len(hostsBytes)/1024)
	log.Printf("Files size - %d kB", (len(filterBytes)+len(hostsBytes))/1024)
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
		rule, found := dnsEngine.Match(reqHostname)
		elapsedMatch := time.Since(startMatch)
		totalElapsed += elapsedMatch
		if elapsedMatch > maxElapsedMatch {
			maxElapsedMatch = elapsedMatch
		}
		if elapsedMatch < minElapsedMatch {
			minElapsedMatch = elapsedMatch
		}

		if found {
			switch v := rule.(type) {
			case *HostRule:
				totalMatches++
			case *NetworkRule:
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

	afterMatch := getRSS()
	log.Printf("RSS after matching - %d kB (%d kB diff)\n", afterMatch/1024, (afterMatch-afterLoad)/1024)
}

func TestDNSEngineMatchHostname(t *testing.T) {
	filterLists := map[int]string{
		1: "||example.org^\n0.0.0.0 example.com",
	}

	ruleStorage, err := NewRuleStorage("")
	if err != nil {
		t.Fatalf("cannot initialize rule storage: %s", err)
	}
	dnsEngine := ParseDNSEngine(filterLists, ruleStorage)
	assert.NotNil(t, dnsEngine)

	r, ok := dnsEngine.Match("example.org")
	assert.True(t, ok)

	_, ok = r.(*NetworkRule)
	assert.True(t, ok)

	r, ok = dnsEngine.Match("example.com")
	assert.True(t, ok)

	_, ok = r.(*HostRule)
	assert.True(t, ok)

	_, ok = dnsEngine.Match("example.net")
	assert.False(t, ok)
}
