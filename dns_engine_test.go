package urlfilter

import (
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	networkFilterPath = testResourcesDir + "/adguard_sdn_filter.txt"
	hostsPath         = testResourcesDir + "/hosts"
	pprofFilePath     = testResourcesDir + "/dnsengine.pprof"
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

	start := getRSS()
	log.Printf("RSS before loading rules - %d kB", start/1024)

	ruleStorage, err := NewRuleStorage("")
	if err != nil {
		t.Fatalf("cannot initialize rule storage: %s", err)
	}
	defer ruleStorage.Close()

	startParse := time.Now()
	dnsEngine := ParseDNSEngine(filterLists, ruleStorage)
	assert.NotNil(t, dnsEngine)

	// Save pprof
	f, err := os.Create(pprofFilePath)
	if err != nil {
		log.Fatal("could not create memory profile: ", err)
	}
	defer f.Close()
	runtime.GC() // get up-to-date statistics
	if err := pprof.WriteHeapProfile(f); err != nil {
		log.Fatal("could not write memory profile: ", err)
	}

	log.Printf("Elapsed on parsing rules: %v", time.Since(startParse))
	log.Printf("Filters size - %d kB", len(filterBytes)/1024)
	log.Printf("Hosts size - %d kB", len(hostsBytes)/1024)
	log.Printf("Files size - %d kB", (len(filterBytes)+len(hostsBytes))/1024)
	log.Printf("Rules count - %v", dnsEngine.RulesCount)

	afterLoad := getRSS()
	log.Printf("RSS after loading rules - %d kB (%d kB diff)", afterLoad/1024, (afterLoad-start)/1024)
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
