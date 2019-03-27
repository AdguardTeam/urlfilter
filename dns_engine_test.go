package urlfilter

import (
	"io/ioutil"
	"log"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	hostsPath = testResourcesDir + "/hosts"
)

func TestBenchDNSEngine(t *testing.T) {
	filterBytes, err := ioutil.ReadFile(filterPath)
	if err != nil {
		t.Fatalf("cannot read %s", filterPath)
	}

	hostsBytes, err := ioutil.ReadFile(hostsPath)
	if err != nil {
		t.Fatalf("cannot read %s", hostsPath)
	}

	filterLists := map[int]string{
		1: string(filterBytes), // (8644 kB engine size)
		2: string(hostsBytes),  // (8440 kB engine size)
	}

	start := getRSS()
	log.Printf("RSS before loading rules - %d kB", start/1024)

	startParse := time.Now()
	dnsEngine := ParseDNSEngine(filterLists)
	assert.NotNil(t, dnsEngine)
	log.Printf("Elapsed on parsing rules: %v", time.Since(startParse))
	log.Printf("Files size - %d kB", (len(filterBytes)+len(hostsBytes))/1024)
	log.Printf("Rules count - %v", dnsEngine.RulesCount)

	afterLoad := getRSS()
	log.Printf("RSS after loading rules - %d kB (%d kB diff)", afterLoad/1024, (afterLoad-start)/1024)
}

func TestDNSEngineMatchHostname(t *testing.T) {
	filterLists := map[int]string{
		1: "||example.org^\n0.0.0.0 example.com",
	}
	dnsEngine := ParseDNSEngine(filterLists)
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
