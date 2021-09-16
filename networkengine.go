package urlfilter

import (
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/lookup"
	"github.com/AdguardTeam/urlfilter/rules"
)

// NetworkEngine is the engine that supports quick search over network rules.
type NetworkEngine struct {
	// RulesCount is the count of rules added to the engine.
	RulesCount int

	// ruleStorage is a storage for the network rules.  We try to avoid keeping
	// rules.NetworkRule structs in memory so instead of that we use their
	// indexes and retrieve them from the storage when it's needed.
	ruleStorage *filterlist.RuleStorage

	// lookupTables is the array of lookup tables which we need to speed up
	// the matching speed.  Note, that the order of lookup tables is very
	// important, we'll try to add rules to the faster table first. If it's not
	// eligible for that lookup table, we'll then proceed to a slower one.
	lookupTables []lookup.Table
}

// NewNetworkEngine builds an instance of the network engine. This method scans
// the specified rule storage and adds all rules.NetworkRule found there to the
// internal lookup tables.
func NewNetworkEngine(s *filterlist.RuleStorage) (engine *NetworkEngine) {
	engine = NewNetworkEngineSkipStorageScan(s)
	scanner := s.NewRuleStorageScanner()

	for scanner.Scan() {
		f, idx := scanner.Rule()
		rule, ok := f.(*rules.NetworkRule)
		if ok {
			engine.AddRule(rule, idx)
		}
	}

	return engine
}

// NewNetworkEngineSkipStorageScan creates a new instance of *NetworkEngine, but
// unlike NewNetworkEngine it does not scans the storage.
func NewNetworkEngineSkipStorageScan(s *filterlist.RuleStorage) (engine *NetworkEngine) {
	return &NetworkEngine{
		ruleStorage: s,
		lookupTables: []lookup.Table{
			lookup.NewShortcutsTable(s),
			lookup.NewDomainsTable(s),
			&lookup.SeqScanTable{},
		},
	}
}

// Match searches over all filtering rules loaded to the engine.
// It returns true if a match was found alongside the matching rule.
func (n *NetworkEngine) Match(r *rules.Request) (*rules.NetworkRule, bool) {
	networkRules := n.MatchAll(r)

	if len(networkRules) == 0 {
		return nil, false
	}

	result := rules.NewMatchingResult(networkRules, nil)
	resultRule := result.GetBasicResult()
	return resultRule, resultRule != nil
}

// MatchAll finds all rules matching the specified request regardless of
// the rule types.  It will find both allowlist and blocklist rules.
func (n *NetworkEngine) MatchAll(r *rules.Request) (result []*rules.NetworkRule) {
	for _, table := range n.lookupTables {
		result = append(result, table.MatchAll(r)...)
	}

	return result
}

// AddRule adds rule to the network engine.
func (n *NetworkEngine) AddRule(f *rules.NetworkRule, storageIdx int64) {
	for _, table := range n.lookupTables {
		if table.TryAdd(f, storageIdx) {
			n.RulesCount++
			return
		}
	}
}
