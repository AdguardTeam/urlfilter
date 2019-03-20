package urlfilter

import (
	"math"
	"strings"
)

const (
	shortcutLength = 5
)

// NetworkEngine is the engine that supports quick search over network rules
type NetworkEngine struct {
	domainsLookupTable   map[uint32][]*NetworkRule
	shortcutsLookupTable map[uint32][]*NetworkRule
	shortcutsHistogram   map[uint32]int
	otherRules           []*NetworkRule
}

// NewNetworkEngine builds an instance of the network engine
func NewNetworkEngine(rules []*NetworkRule) *NetworkEngine {
	engine := NetworkEngine{
		domainsLookupTable:   map[uint32][]*NetworkRule{},
		shortcutsLookupTable: map[uint32][]*NetworkRule{},
		shortcutsHistogram:   map[uint32]int{},
	}

	for i := range rules {
		rule := rules[i]
		engine.addRule(rule)
	}

	return &engine
}

// Match searches over all filtering rules loaded to the engine
// It returns true if a match was found alongside the matching rule
func (n *NetworkEngine) Match(r *Request) (bool, *NetworkRule) {
	rules := n.MatchAll(r)

	if len(rules) == 0 {
		return false, nil
	}

	for i := range rules {
		rule := rules[i]
		if rule.Whitelist {
			return true, rule
		}
	}

	return true, rules[0]
}

// MatchAll finds all rules matching the specified request regardless of the rule types
// It will find both whitelist and blacklist rules
func (n *NetworkEngine) MatchAll(r *Request) []*NetworkRule {
	// First check by shortcuts
	result := n.matchShortcutsLookupTable(r)

	for _, rule := range n.matchDomainsLookupTable(r) {
		result = append(result, rule)
	}

	// Now check other rules
	for i := range n.otherRules {
		rule := n.otherRules[i]
		if rule.Match(r) {
			result = append(result, rule)
		}
	}

	return result
}

// matchShortcutsLookupTable finds all matching rules from the shortcuts lookup table
func (n *NetworkEngine) matchShortcutsLookupTable(r *Request) []*NetworkRule {
	var result []*NetworkRule
	for i := 0; i <= len(r.URLLowerCase)-shortcutLength; i++ {
		hash := djb2HashBetween(r.URLLowerCase, i, i+shortcutLength)
		if rules, ok := n.shortcutsLookupTable[hash]; ok {
			for i := range rules {
				rule := rules[i]
				if rule.Match(r) {
					result = append(result, rule)
				}
			}
		}
	}

	return result
}

// matchDomainsLookupTable finds all matching rules from the domains lookup table
func (n *NetworkEngine) matchDomainsLookupTable(r *Request) []*NetworkRule {
	var result []*NetworkRule

	if r.SourceHostname == "" {
		return result
	}

	domains := getSubdomains(r.SourceHostname)
	for _, domain := range domains {
		hash := djb2Hash(domain)
		if rules, ok := n.domainsLookupTable[hash]; ok {
			for i := range rules {
				rule := rules[i]
				if rule.Match(r) {
					result = append(result, rule)
				}
			}
		}
	}
	return result
}

// addRule adds rule to the network engine
func (n *NetworkEngine) addRule(f *NetworkRule) {
	if !n.addRuleToShortcutsTable(f) {
		if !n.addRuleToDomainsTable(f) {
			n.otherRules = append(n.otherRules, f)
		}
	}
}

// addRuleToDomainsTable tries to add the rule to the domains lookup table.
// returns true if it was added (the domain
func (n *NetworkEngine) addRuleToDomainsTable(f *NetworkRule) bool {
	if len(f.permittedDomains) == 0 {
		return false
	}

	for _, domain := range f.permittedDomains {
		hash := djb2Hash(domain)

		// Add the rule to the lookup table
		rules, _ := n.domainsLookupTable[hash]
		rules = append(rules, f)
		n.domainsLookupTable[hash] = rules
	}

	return true
}

// addRuleToShortcutsTable tries to add the rule to the shortcuts table.
// returns true if it was added or false if the shortcut is too short
func (n *NetworkEngine) addRuleToShortcutsTable(f *NetworkRule) bool {
	shortcuts := getRuleShortcuts(f)
	if len(shortcuts) == 0 {
		return false
	}

	// Find the applicable shortcut (the least used)
	var shortcutHash uint32
	var minCount = math.MaxInt32
	for _, shortcutToCheck := range shortcuts {
		hash := djb2Hash(shortcutToCheck)
		count, ok := n.shortcutsHistogram[hash]
		if !ok {
			count = 0
		}
		if count < minCount {
			minCount = count
			shortcutHash = hash
		}
	}

	// Increment the histogram
	n.shortcutsHistogram[shortcutHash] = minCount + 1

	// Add the rule to the lookup table
	rules, _ := n.shortcutsLookupTable[shortcutHash]
	rules = append(rules, f)
	n.shortcutsLookupTable[shortcutHash] = rules

	return true
}

// getRuleShortcuts returns a list of shortcuts that can be used for the lookup table
func getRuleShortcuts(f *NetworkRule) []string {
	if len(f.Shortcut) < shortcutLength {
		return nil
	}

	if isAnyURLShortcut(f) {
		return nil
	}

	var shortcuts []string
	for i := 0; i <= len(f.Shortcut)-shortcutLength; i++ {
		shortcut := f.Shortcut[i : i+shortcutLength]
		shortcuts = append(shortcuts, shortcut)
	}

	return shortcuts
}

// isAnyURLShortcut checks if the rule potentially matches too many URLs.
// We'd better use another type of lookup table for this kind of rules.
func isAnyURLShortcut(f *NetworkRule) bool {
	// Sorry for magic numbers
	// The numbers are basically ("PROTO://".length + 1)

	if len(f.Shortcut) < 6 && strings.Index(f.Shortcut, "ws:") == 0 {
		return true
	}

	if len(f.Shortcut) < 7 && strings.Index(f.Shortcut, "|ws") == 0 {
		return true
	}

	if len(f.Shortcut) < 9 && strings.Index(f.Shortcut, "http") == 0 {
		return true
	}

	if len(f.Shortcut) < 10 && strings.Index(f.Shortcut, "|http") == 0 {
		return true
	}

	return false
}

// djb2 hash algorithm
func djb2HashBetween(str string, begin int, end int) uint32 {
	hash := uint32(5381)
	for i := begin; i < end; i++ {
		hash = (hash * 33) ^ uint32(str[i])
	}
	return hash
}

// djb2 hash algorithm
func djb2Hash(str string) uint32 {
	if str == "" {
		return 0
	}
	return djb2HashBetween(str, 0, len(str))
}
