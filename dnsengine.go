package urlfilter

import (
	"net/netip"

	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/internal/fasthash"
	"github.com/AdguardTeam/urlfilter/rules"
)

// DNSEngine combines host rules and network rules and is supposed to quickly find
// matching rules for hostnames.
// First, it looks over network rules and returns first rule found.
// Then, if nothing found, it looks up the host rules.
type DNSEngine struct {
	// lookupTable is a map for hosts hashes mapped to the list of rule indexes.
	lookupTable map[uint32][]int64

	// networkEngine is a network rules engine constructed from the network
	// rules.
	networkEngine *NetworkEngine

	// rulesStorage is the storage of all rules.
	rulesStorage *filterlist.RuleStorage

	// pool is the pool of [rules.Request] values.
	pool *syncutil.Pool[rules.Request]

	// RulesCount is the count of rules loaded to the engine.
	RulesCount int
}

// DNSResult is the result of matching a DNS filtering request.
type DNSResult struct {
	// NetworkRule is the matched network rule, if any.  If it is nil,
	// HostRulesV4 and HostRulesV6 may still contain matched hosts-file style
	// rules.
	NetworkRule *rules.NetworkRule

	// HostRulesV4 are the host rules with IPv4 addresses.
	HostRulesV4 []*rules.HostRule

	// HostRulesV6 are the host rules with IPv6 addresses.
	HostRulesV6 []*rules.HostRule

	// NetworkRules are all matched network rules.  These include unprocessed
	// DNS rewrites, exception rules, and so on.
	NetworkRules []*rules.NetworkRule
}

// DNSRequest represents a DNS query with associated metadata.
type DNSRequest struct {
	// ClientIP is the IP address to match against $client modifiers.  The
	// default zero value won't be considered.
	ClientIP netip.Addr

	// ClientName is the name to match against $client modifiers.  The default
	// empty value won't be considered.
	ClientName string

	// Hostname is the hostname to filter.
	Hostname string

	// SortedClientTags is the list of tags to match against $ctag modifiers.
	SortedClientTags []string

	// DNSType is the type of the resource record (RR) of a DNS request, for
	// example "A" or "AAAA".  See [rules.RRValue] for all acceptable constants
	// and their corresponding values.
	DNSType rules.RRType

	// Answer if the filtering request is for filtering a DNS response.
	Answer bool
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
		switch f := f.(type) {
		case *rules.HostRule:
			hostRulesCount += len(f.Hostnames)
		case *rules.NetworkRule:
			networkRulesCount++
		}
	}

	// Initialize the DNSEngine using these newly acquired numbers
	d := DNSEngine{
		rulesStorage: s,
		lookupTable:  make(map[uint32][]int64, hostRulesCount),
		RulesCount:   0,
		pool: syncutil.NewPool(func() (v *rules.Request) {
			return &rules.Request{}
		}),
	}

	networkEngine := NewNetworkEngineSkipStorageScan(s)

	// Go through all rules in the storage and add them to the lookup tables
	scanner := s.NewRuleStorageScanner()
	for scanner.Scan() {
		f, idx := scanner.Rule()
		switch f := f.(type) {
		case *rules.HostRule:
			d.addRule(f, idx)
		case *rules.NetworkRule:
			if f.IsHostLevelNetworkRule() {
				networkEngine.AddRule(f, idx)
			}
		}
	}

	d.RulesCount += networkEngine.RulesCount
	d.networkEngine = networkEngine

	return &d
}

// Match finds a matching rule for the specified hostname.  It returns true and
// the list of rules found or false and nil.  A list of rules is returned when
// there are multiple host rules matching the same domain, for example:
//
//	192.168.0.1 example.local
//	2000::1 example.local
func (d *DNSEngine) Match(hostname string) (res *DNSResult, matched bool) {
	return d.MatchRequest(&DNSRequest{Hostname: hostname})
}

// getRequestFromPool returns an instance of request from the engine's pool.
// Fills it's properties to match the given DNS request.
func (d *DNSEngine) getRequestFromPool(dReq *DNSRequest) (req *rules.Request) {
	req = d.pool.Get()

	req.SourceDomain = ""
	req.SourceHostname = ""
	req.SourceURL = ""

	req.SortedClientTags = dReq.SortedClientTags
	req.ClientIP = dReq.ClientIP
	req.ClientName = dReq.ClientName
	req.DNSType = dReq.DNSType

	rules.FillRequestForHostname(req, dReq.Hostname)

	return req
}

// MatchRequest matches the specified DNS request.  The return parameter matched
// is true if the result has a basic network rule or some host rules.
//
// For compatibility reasons, it is also false when there are DNS rewrite and
// other kinds of special network rules, so users who need those will need to
// ignore the matched return parameter and instead inspect the results of the
// corresponding DNSResult getters.
//
// TODO(ameshkov): return nil when there's no match. Currently, the logic is
// flawed because it analyzes the DNSResult even when matched is false and looks
// for $dnsrewrite rules.
func (d *DNSEngine) MatchRequest(dReq *DNSRequest) (res *DNSResult, matched bool) {
	res = &DNSResult{}

	if dReq.Hostname == "" {
		return res, false
	}

	r := d.getRequestFromPool(dReq)
	defer d.pool.Put(r)

	res.NetworkRules = d.networkEngine.MatchAll(r)
	resultRule := rules.GetDNSBasicRule(res.NetworkRules)
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
		hostRule, idHostRule := rule.(*rules.HostRule)
		if !idHostRule {
			continue
		}

		if hostRule.IP.Is4() {
			res.HostRulesV4 = append(res.HostRulesV4, hostRule)
		} else {
			res.HostRulesV6 = append(res.HostRulesV6, hostRule)
		}
	}

	return res, true
}

// matchLookupTable looks for matching rules in the d.lookupTable
func (d *DNSEngine) matchLookupTable(hostname string) ([]rules.Rule, bool) {
	hash := fasthash.String(hostname)
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
		hash := fasthash.String(hostname)
		rulesIndexes := d.lookupTable[hash]
		d.lookupTable[hash] = append(rulesIndexes, storageIdx)
	}

	d.RulesCount++
}
