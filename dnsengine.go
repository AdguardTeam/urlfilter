package urlfilter

import (
	"net/netip"

	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
)

// DNSEngine combines host rules and network rules and is supposed to quickly find
// matching rules for hostnames.
// First, it looks over network rules and returns first rule found.
// Then, if nothing found, it looks up the host rules.
type DNSEngine struct {
	// ruleIndex is a map for hosts mapped to the list of rule indexes.
	ruleIndex map[string][]filterlist.StorageID

	// networkEngine is a network rules engine constructed from the network
	// rules.
	networkEngine *NetworkEngine

	// rulesStorage is the storage of all rules.
	rulesStorage *filterlist.RuleStorage

	// reqPool is the pool of [rules.Request] values.
	reqPool *syncutil.Pool[rules.Request]

	// rulesPool contains slices of rules for reuse.
	rulesPool *syncutil.Pool[[]*rules.HostRule]

	// RulesCount is the count of rules loaded to the engine.
	RulesCount int
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

// Reset makes r ready for reuse.
func (r *DNSRequest) Reset() {
	r.ClientIP = netip.Addr{}

	r.ClientName = ""
	r.Hostname = ""

	r.SortedClientTags = r.SortedClientTags[:0]

	r.DNSType = 0

	r.Answer = false
}

// bytesPerRuleEst is the estimate of how many bytes a single rule generally
// takes.  It is based on the AdGuard Base DNS list.
const bytesPerRuleEst = 64

// NewDNSEngine parses the specified filter lists and returns a *DNSEngine built
// from them.  s must not be nil.
func NewDNSEngine(s *filterlist.RuleStorage) (d *DNSEngine) {
	numRulesEst := s.SizeEstimate() / bytesPerRuleEst

	d = &DNSEngine{
		rulesStorage: s,
		ruleIndex:    make(map[string][]filterlist.StorageID, numRulesEst),
		RulesCount:   0,
		reqPool:      syncutil.NewPool(func() (v *rules.Request) { return &rules.Request{} }),
		rulesPool:    syncutil.NewSlicePool[*rules.HostRule](1),
	}

	netEng := NewNetworkEngineSkipStorageScan(s)
	scanner := s.NewRuleStorageScanner()
	for scanner.Scan() {
		f, id := scanner.Rule()
		switch f := f.(type) {
		case *rules.HostRule:
			d.addRule(f, id)
		case *rules.NetworkRule:
			if f.IsHostLevelNetworkRule() {
				netEng.AddRule(f, id)
			}
		}
	}

	d.RulesCount += netEng.RulesCount
	d.networkEngine = netEng

	return d
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
	req = d.reqPool.Get()

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

// MatchRequestInto matches the specified DNS request and puts the result into
// res.  ok is true if the result has a basic network rule or some host rules.
// req and res must not be nil.  res should be empty or reset using
// [DNSResult.Reset].
//
// NOTE:  For compatibility reasons, it is also false when there are DNS rewrite
// and other kinds of special network rules, so users who need those will need
// to ignore the matched return parameter and instead inspect the results of the
// corresponding DNSResult getters.
//
// TODO(a.garipov):  Refactor the result and remove the exception above.
func (d *DNSEngine) MatchRequestInto(req *DNSRequest, res *DNSResult) (matched bool) {
	if req.Hostname == "" {
		return false
	}

	r := d.getRequestFromPool(req)
	defer d.reqPool.Put(r)

	res.NetworkRules = d.networkEngine.AppendAllMatching(res.NetworkRules, r)
	resultRule := rules.GetDNSBasicRule(res.NetworkRules)
	if resultRule != nil {
		res.NetworkRule = resultRule

		return true
	}

	hostRulesPtr := d.rulesPool.Get()
	defer d.rulesPool.Put(hostRulesPtr)

	*hostRulesPtr = d.appendFromIndex((*hostRulesPtr)[:0], req.Hostname)
	if len(*hostRulesPtr) == 0 {
		return false
	}

	for _, rule := range *hostRulesPtr {
		if rule.IP.Is4() {
			res.HostRulesV4 = append(res.HostRulesV4, rule)
		} else {
			res.HostRulesV6 = append(res.HostRulesV6, rule)
		}
	}

	return true
}

// MatchRequest is like [MatchRequestInto] but returns a new result.  req must
// not be nil.
func (d *DNSEngine) MatchRequest(dReq *DNSRequest) (res *DNSResult, matched bool) {
	res = &DNSResult{}
	matched = d.MatchRequestInto(dReq, res)

	return res, matched
}

// appendFromIndex appends matching rules to matching.
func (d *DNSEngine) appendFromIndex(
	matching []*rules.HostRule,
	hostname string,
) (res []*rules.HostRule) {
	res = matching

	ids := d.ruleIndex[hostname]
	for _, id := range ids {
		res = append(res, d.rulesStorage.RetrieveHostRule(id))
	}

	return res
}

// addRule adds rule to the index
func (d *DNSEngine) addRule(hostRule *rules.HostRule, id filterlist.StorageID) {
	for _, hostname := range hostRule.Hostnames {
		d.ruleIndex[hostname] = append(d.ruleIndex[hostname], id)
	}

	d.RulesCount++
}
