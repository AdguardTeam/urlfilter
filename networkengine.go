package urlfilter

import (
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/internal/lookup"
	"github.com/AdguardTeam/urlfilter/rules"
)

// NetworkEngine is the engine that supports quick search over network rules.
type NetworkEngine struct {
	// ruleStorage stores network rules.
	ruleStorage *filterlist.RuleStorage

	// rulesPool contains slices of rules for reuse.
	rulesPool *syncutil.Pool[[]*rules.NetworkRule]

	// lookupTables speed up the matching.
	//
	// NOTE:  The order of lookup tables is very important, as the rules are
	// added to the faster table first.
	lookupTables []lookup.Table

	// RulesCount is the count of rules added to the engine.
	//
	// TODO(a.garipov):  Unexport and export a getter method.
	RulesCount int
}

// NewNetworkEngine builds an instance of the network engine.  It scans the
// specified rule storage and adds all network rules found there to the internal
// lookup tables.
func NewNetworkEngine(s *filterlist.RuleStorage) (engine *NetworkEngine) {
	engine = NewNetworkEngineSkipStorageScan(s)
	scanner := s.NewRuleStorageScanner()

	for scanner.Scan() {
		f, id := scanner.Rule()
		rule, ok := f.(*rules.NetworkRule)
		if ok {
			engine.AddRule(rule, id)
		}
	}

	return engine
}

// NewNetworkEngineSkipStorageScan creates a new instance of *NetworkEngine, but
// unlike [NewNetworkEngine] it does not scan the storage.
func NewNetworkEngineSkipStorageScan(s *filterlist.RuleStorage) (engine *NetworkEngine) {
	return &NetworkEngine{
		ruleStorage: s,
		rulesPool:   syncutil.NewSlicePool[*rules.NetworkRule](1),
		lookupTables: []lookup.Table{
			lookup.NewShortcutsTable(s),
			lookup.NewDomainsTable(s),
			&lookup.SeqScanTable{},
		},
	}
}

// Match searches over all filtering rules loaded to the engine and returns true
// if a match was found alongside the matching rule.  r must not be nil.
func (n *NetworkEngine) Match(r *rules.Request) (rule *rules.NetworkRule, ok bool) {
	rulesPtr := n.rulesPool.Get()
	defer n.rulesPool.Put(rulesPtr)

	*rulesPtr = n.AppendAllMatching((*rulesPtr)[:0], r)
	if len(*rulesPtr) == 0 {
		return nil, false
	}

	result := rules.NewMatchingResult(*rulesPtr, nil)
	resultRule := result.GetBasicResult()

	return resultRule, resultRule != nil
}

// MatchAll finds all rules matching the specified request regardless of the
// rule types.  It will find both allowlist and blocklist rules.  r must not be
// nil.
//
// Deprecated:  Use [NetworkEngine.AppendAllMatching] instead.
func (n *NetworkEngine) MatchAll(r *rules.Request) (res []*rules.NetworkRule) {
	return n.AppendAllMatching(nil, r)
}

// AppendAllMatching appends all rules matching the specified request,
// regardless of the rule types, to matching.  It will find both allowlist and
// blocklist rules.  r must not be nil.
func (n *NetworkEngine) AppendAllMatching(
	matching []*rules.NetworkRule,
	r *rules.Request,
) (res []*rules.NetworkRule) {
	res = matching
	for _, table := range n.lookupTables {
		res = table.AppendMatching(res, r)
	}

	return res
}

// AddRule adds rule to the network engine.  r must not be nil.
func (n *NetworkEngine) AddRule(r *rules.NetworkRule, id filterlist.StorageID) {
	for _, table := range n.lookupTables {
		if table.Add(r, id) {
			n.RulesCount++

			return
		}
	}
}
