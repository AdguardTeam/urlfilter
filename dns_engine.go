package urlfilter

// DNSEngine combines host rules and network rules and is supposed to quickly find
// matching rules for hostnames.
// First, it looks over network rules and returns first rule found.
// Then, if nothing found, it looks up the host rules.
type DNSEngine struct {
	RulesCount              int              // count of rules loaded to the engine
	networkEngine           *NetworkEngine   // networkEngine is constructed from the network rules
	hostRulesLookupTable    map[string]int64 // map for hosts mapped to IPv4 addresses
	hostRulesLookupTableIP6 map[string]int64 // map for hosts mapped to IPv6 addresses
	rulesStorage            *RuleStorage
}

// NewDNSEngine parses the specified filter lists and returns a DNSEngine built from them.
// key of the map is the filter list ID, value is the raw content of the filter list.
func NewDNSEngine(s *RuleStorage) *DNSEngine {
	d := DNSEngine{
		rulesStorage:            s,
		hostRulesLookupTable:    map[string]int64{},
		hostRulesLookupTableIP6: map[string]int64{},
		RulesCount:              0,
	}

	networkEngine := &NetworkEngine{
		ruleStorage:          s,
		domainsLookupTable:   map[uint32][]int64{},
		shortcutsLookupTable: map[uint32][]int64{},
		shortcutsHistogram:   map[uint32]int{},
	}

	scanner := s.NewRuleStorageScanner()
	for scanner.Scan() {
		f, idx := scanner.Rule()

		if hostRule, ok := f.(*HostRule); ok {
			for _, hostname := range hostRule.Hostnames {
				if hostRule.IP.To4() == nil {
					d.hostRulesLookupTableIP6[hostname] = idx
				} else {
					d.hostRulesLookupTable[hostname] = idx
				}
			}
			d.RulesCount++
		} else if networkRule, ok := f.(*NetworkRule); ok {
			if isHostLevelNetworkRule(networkRule) {
				networkEngine.addRule(networkRule, idx)
			}
		}
	}

	d.RulesCount += networkEngine.RulesCount
	d.networkEngine = networkEngine
	return &d
}

// Match finds a matching rule for the specified hostname.
// It returns true and the list of rules found or false and nil.
// The list of rules can be found when there're multiple host rules matching the same domain.
// For instance:
// 192.168.0.1 example.local
// 2000::1 example.local
func (d *DNSEngine) Match(hostname string) ([]Rule, bool) {
	if hostname == "" {
		return nil, false
	}

	r := NewRequestForHostname(hostname)
	networkRule, ok := d.networkEngine.Match(r)
	if ok {
		return []Rule{networkRule}, true
	}

	var rules []Rule

	if rule, ok := d.matchHostRulesLookupTable(hostname, d.hostRulesLookupTable); ok {
		rules = append(rules, rule)
	}

	if rule, ok := d.matchHostRulesLookupTable(hostname, d.hostRulesLookupTableIP6); ok {
		rules = append(rules, rule)
	}

	return rules, len(rules) > 0
}

// matchHostRulesLookupTable looks for a matching rule in the specified lookup table
func (d *DNSEngine) matchHostRulesLookupTable(hostname string, lookupTable map[string]int64) (*HostRule, bool) {
	hostRuleIdx, found := lookupTable[hostname]
	if !found {
		return nil, false
	}

	rule := d.rulesStorage.RetrieveHostRule(hostRuleIdx)
	if rule != nil && rule.Match(hostname) {
		return rule, true
	}

	return nil, false
}

// isHostLevelNetworkRule checks if this rule can be used for hosts-level blocking
func isHostLevelNetworkRule(r *NetworkRule) bool {
	if len(r.permittedDomains) > 0 || len(r.restrictedDomains) > 0 {
		return false
	}

	if r.permittedRequestTypes != 0 && r.restrictedRequestTypes != 0 {
		return false
	}

	// The only allowed option is $important
	if r.enabledOptions != 0 && r.enabledOptions != OptionImportant {
		return false
	}

	return true
}
