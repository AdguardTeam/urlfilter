package urlfilter

import "strings"

// DNSEngine combines host rules and network rules and is supposed to quickly find
// matching rules for hostnames.
// First, it looks over network rules and returns first rule found.
// Then, if nothing found, it looks up the host rules.
type DNSEngine struct {
	RulesCount           int            // count of rules loaded to the engine
	networkEngine        *NetworkEngine // networkEngine is constructed from the network rules
	hostRulesLookupTable map[string]*HostRule
}

// ParseDNSEngine parses the specified filter lists and returns a DNSEngine built from them.
// key of the map is the filter list ID, value is the raw content of the filter list.
func ParseDNSEngine(filterLists map[int]string) *DNSEngine {
	var networkRules []*NetworkRule
	var hostRules []*HostRule

	for filterListID, filterContents := range filterLists {
		lines := strings.Split(filterContents, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || isComment(line) || isCosmetic(line) {
				continue
			}

			hostRule, err := NewHostRule(line, filterListID)
			if err == nil {
				hostRules = append(hostRules, hostRule)
			} else {
				networkRule, err := NewNetworkRule(line, filterListID)
				if err == nil && isHostLevelNetworkRule(networkRule) {
					networkRules = append(networkRules, networkRule)
				}
			}
		}
	}

	return NewDNSEngine(networkRules, hostRules)
}

// NewDNSEngine creates a new instance of the DNSEngine
func NewDNSEngine(networkRules []*NetworkRule, hostRules []*HostRule) *DNSEngine {
	d := DNSEngine{
		networkEngine:        NewNetworkEngine(networkRules),
		hostRulesLookupTable: map[string]*HostRule{},
		RulesCount:           len(networkRules) + len(hostRules),
	}

	// Populate the host rules lookup table
	for _, h := range hostRules {
		for _, hostname := range h.Hostnames {
			d.hostRulesLookupTable[hostname] = h
		}
	}

	return &d
}

// Match finds a matching rule for the specified hostname
// It returns true and the rule found or false and nil
func (d *DNSEngine) Match(hostname string) (Rule, bool) {
	if hostname == "" {
		return nil, false
	}

	r := NewRequestForHostname(hostname)
	networkRule, ok := d.networkEngine.Match(r)
	if ok {
		return networkRule, true
	}

	hostRule, found := d.hostRulesLookupTable[hostname]
	if found && hostRule.Match(r.Hostname) {
		return hostRule, true
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
