package urlfilter

import (
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/filterutil"
	"github.com/AdguardTeam/urlfilter/rules"
)

// DNSEngine combines host rules and network rules and is supposed to quickly find
// matching rules for hostnames.
// First, it looks over network rules and returns first rule found.
// Then, if nothing found, it looks up the host rules.
type DNSEngine struct {
	RulesCount    int                // count of rules loaded to the engine
	networkEngine *NetworkEngine     // networkEngine is constructed from the network rules
	lookupTable   map[uint32][]int64 // map for hosts hashes mapped to the list of rule indexes
	rulesStorage  *filterlist.RuleStorage
}

// DNSResult - the return value of Match() function
type DNSResult struct {
	NetworkRule *rules.NetworkRule // a network rule or nil
	HostRulesV4 []*rules.HostRule  // host rules for IPv4 or nil
	HostRulesV6 []*rules.HostRule  // host rules for IPv6 or nil

	// networkRules are all matched network rules.
	networkRules []*rules.NetworkRule
}

// DNSRequest represents a DNS query with associated metadata.
type DNSRequest struct {
	Hostname string // Hostname (or IP address)

	Answer           bool     // If true - this hostname or IP is from a DNS response
	SortedClientTags []string // Sorted list of client tags ($ctag)
	ClientIP         string   // Client IP address
	ClientName       string   // Client name

	// DNSType is the type of the resource record (RR) of a DNS request, for
	// example "A" or "AAAA".  See package github.com/miekg/dns for all
	// acceptable constants.
	DNSType rules.RRType
}

// NewDNSEngine parses the specified filter lists and returns a DNSEngine built from them.
// key of the map is the filter list ID, value is the raw content of the filter list.
func NewDNSEngine(s *filterlist.RuleStorage) *DNSEngine {
	// At first, we count rules in the rule storage so that we could pre-allocate lookup tables
	// Surprisingly, this helps us save a lot on allocations
	var hostRulesCount, networkRulesCount int
	scan := s.NewRuleStorageScanner()
	for scan.Scan() {
		f, _ := scan.Rule()
		if hostRule, ok := f.(*rules.HostRule); ok {
			hostRulesCount += len(hostRule.Hostnames)
		} else if _, ok := f.(*rules.NetworkRule); ok {
			networkRulesCount++
		}
	}

	// Initialize the DNSEngine using these newly acquired numbers
	d := DNSEngine{
		rulesStorage: s,
		lookupTable:  make(map[uint32][]int64, hostRulesCount),
		RulesCount:   0,
	}

	networkEngine := NewNetworkEngineSkipStorageScan(s)

	// Go through all rules in the storage and add them to the lookup tables
	scanner := s.NewRuleStorageScanner()
	for scanner.Scan() {
		f, idx := scanner.Rule()

		if hostRule, ok := f.(*rules.HostRule); ok {
			d.addRule(hostRule, idx)
		} else if networkRule, ok := f.(*rules.NetworkRule); ok {
			if networkRule.IsHostLevelNetworkRule() {
				networkEngine.AddRule(networkRule, idx)
			}
		}
	}

	d.RulesCount += networkEngine.RulesCount
	d.networkEngine = networkEngine
	return &d
}

// Match finds a matching rule for the specified hostname.
//
// It returns true and the list of rules found or false and nil.
// The list of rules can be found when there're multiple host rules matching the same domain.
// For instance:
// 192.168.0.1 example.local
// 2000::1 example.local
func (d *DNSEngine) Match(hostname string) (*DNSResult, bool) {
	return d.MatchRequest(DNSRequest{Hostname: hostname, ClientIP: "0.0.0.0"})
}

// MatchRequest matches the specified DNS request.  The return parameter
// matched is true if the result has a basic network rule or some host
// rules.
//
// For compatibility reasons, it is also false when there are DNS
// rewrite and other kinds of special network rules, so users who need
// those will need to ignore the matched return parameter and instead
// inspect the results of the corresponding DNSResult getters.
//
// TODO(ameshkov): return nil when there's no match. Currently, the logic is
// flawed because it analyzes the DNSResult even when matched is false and
// looks for $dnsrewrite rules.
func (d *DNSEngine) MatchRequest(dReq DNSRequest) (res *DNSResult, matched bool) {
	res = &DNSResult{}

	if dReq.Hostname == "" {
		return res, false
	}

	r := rules.NewRequestForHostname(dReq.Hostname)
	r.SortedClientTags = dReq.SortedClientTags
	r.ClientIP = dReq.ClientIP
	r.ClientName = dReq.ClientName
	r.DNSType = dReq.DNSType

	res.networkRules = d.networkEngine.MatchAll(r)

	result := rules.NewMatchingResult(res.networkRules, nil)
	resultRule := result.GetBasicResult()
	if resultRule != nil {
		// Network rules always have higher priority.
		res.NetworkRule = resultRule
		return res, true
	}

	rr, ok := d.matchLookupTable(dReq.Hostname)
	if !ok {
		return res, false
	}

	for _, rule := range rr {
		hostRule, ok := rule.(*rules.HostRule)
		if !ok {
			continue
		}

		if hostRule.IP.To4() != nil {
			res.HostRulesV4 = append(res.HostRulesV4, hostRule)
		} else {
			res.HostRulesV6 = append(res.HostRulesV6, hostRule)
		}
	}

	return res, true
}

// matchLookupTable looks for matching rules in the d.lookupTable
func (d *DNSEngine) matchLookupTable(hostname string) ([]rules.Rule, bool) {
	hash := filterutil.FastHash(hostname)
	rulesIndexes, ok := d.lookupTable[hash]
	if !ok {
		return nil, false
	}

	var matchingRules []rules.Rule
	for _, idx := range rulesIndexes {
		rule := d.rulesStorage.RetrieveHostRule(idx)
		if rule != nil && rule.Match(hostname) {
			matchingRules = append(matchingRules, rule)
		}
	}

	return matchingRules, len(matchingRules) > 0
}

// addRule adds rule to the index
func (d *DNSEngine) addRule(hostRule *rules.HostRule, storageIdx int64) {
	for _, hostname := range hostRule.Hostnames {
		hash := filterutil.FastHash(hostname)
		rulesIndexes := d.lookupTable[hash]
		d.lookupTable[hash] = append(rulesIndexes, storageIdx)
	}

	d.RulesCount++
}
