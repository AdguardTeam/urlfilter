package urlfilter

import (
	"bufio"
	"fmt"
	"strings"
)

// DNSEngine combines host rules and network rules and is supposed to quickly find
// matching rules for hostnames.
// First, it looks over network rules and returns first rule found.
// Then, if nothing found, it looks up the host rules.
type DNSEngine struct {
	RulesCount           int            // count of rules loaded to the engine
	networkEngine        *NetworkEngine // networkEngine is constructed from the network rules
	hostRulesLookupTable map[string]int64
	ruleStorage          *RulesStorage
}

// ParseDNSEngine parses the specified filter lists and returns a DNSEngine built from them.
// key of the map is the filter list ID, value is the raw content of the filter list.
func ParseDNSEngine(filterLists map[int]string, s *RulesStorage) *DNSEngine {
	d := DNSEngine{
		ruleStorage:          s,
		hostRulesLookupTable: map[string]int64{},
		RulesCount:           0,
	}

	networkEngine := &NetworkEngine{
		ruleStorage:          s,
		domainsLookupTable:   map[uint32][]int64{},
		shortcutsLookupTable: map[uint32][]int64{},
		shortcutsHistogram:   map[uint32]int{},
	}

	for filterListID, filterContents := range filterLists {
		scanner := bufio.NewScanner(strings.NewReader(filterContents))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || isComment(line) || isCosmetic(line) {
				continue
			}

			hostRule, err := NewHostRule(line, filterListID)
			if err == nil {
				idx, err := s.Store(hostRule)
				if err != nil {
					panic(fmt.Errorf("cannot store rule %s: %s", line, err))
				}

				for _, hostname := range hostRule.Hostnames {
					d.hostRulesLookupTable[hostname] = idx
				}
				d.RulesCount++
			} else {
				networkRule, err := NewNetworkRule(line, filterListID)
				if err == nil && isHostLevelNetworkRule(networkRule) {
					networkEngine.addRule(networkRule)
					d.RulesCount++
				}
			}
		}
	}

	d.networkEngine = networkEngine
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

	hostRuleIdx, found := d.hostRulesLookupTable[hostname]
	if !found {
		return nil, false
	}

	rule := d.ruleStorage.RetrieveHostRule(hostRuleIdx)
	if rule == nil {
		return nil, false
	}

	return rule, rule.Match(r.Hostname)
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
