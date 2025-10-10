package urlfilter

import (
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/internal/lookup"
	"github.com/AdguardTeam/urlfilter/rules"
)

// NetworkEngine is the engine that supports quick search over network rules.
type NetworkEngine struct {
	// ruleStorage stores network rules.
	ruleStorage *filterlist.RuleStorage

	// idsPool contains slices of storage IDs for reuse.
	idsPool *syncutil.Pool[[]filterlist.StorageID]

	// rulesPool contains slices of rules for reuse.
	rulesPool *syncutil.Pool[[]*rules.NetworkRule]

	// shortcutsIndex is the first index to use to speed up the lookup of rules.
	shortcutsIndex *lookup.ShortcutIndex

	// domainsIndex is the second index to use to speed up the lookup of rules.
	domainsIndex *lookup.DomainIndex

	// noIndex contains rules that did not fit into the two previous indexes.
	noIndex []*rules.NetworkRule

	// rulesCount is the number of rules added to the engine.
	rulesCount uint64
}

// NewNetworkEngine builds an instance of the network engine.  It scans the
// specified rule storage and adds all network rules found there to the internal
// indexes.
func NewNetworkEngine(s *filterlist.RuleStorage) (engine *NetworkEngine) {
	engine = NewNetworkEngineSkipStorageScan(s)
	scanner := s.NewRuleStorageScanner()

	set := container.NewMapSet[string]()
	for scanner.Scan() {
		f, id := scanner.Rule()
		rule, ok := f.(*rules.NetworkRule)
		if ok {
			engine.addRule(rule, id, set)
		}
	}

	return engine
}

// addRule adds rule to the network engine.  r and set must not be nil.
func (e *NetworkEngine) addRule(
	r *rules.NetworkRule,
	id filterlist.StorageID,
	set *container.MapSet[string],
) {
	added := e.shortcutsIndex.Add(r, id)
	if added {
		e.rulesCount++

		return
	}

	added = e.domainsIndex.Add(r, id)
	if added {
		e.rulesCount++

		return
	}

	if !added {
		s := r.String()
		if set.Has(s) {
			return
		}

		e.noIndex = append(e.noIndex, r)
		set.Add(s)

		e.rulesCount++
	}
}

// NewNetworkEngineSkipStorageScan creates a new instance of *NetworkEngine, but
// unlike [NewNetworkEngine] it does not scan the storage.
func NewNetworkEngineSkipStorageScan(s *filterlist.RuleStorage) (engine *NetworkEngine) {
	return &NetworkEngine{
		ruleStorage:    s,
		idsPool:        syncutil.NewSlicePool[filterlist.StorageID](1),
		rulesPool:      syncutil.NewSlicePool[*rules.NetworkRule](1),
		shortcutsIndex: lookup.NewShortcutIndex(),
		domainsIndex:   lookup.NewDomainIndex(),
	}
}

// Match searches over all filtering rules loaded to the engine and returns true
// if a match was found alongside the matching rule.  r must not be nil.
func (e *NetworkEngine) Match(r *rules.Request) (rule *rules.NetworkRule, ok bool) {
	rulesPtr := e.rulesPool.Get()
	defer e.rulesPool.Put(rulesPtr)

	*rulesPtr = e.AppendAllMatching((*rulesPtr)[:0], r)
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
func (e *NetworkEngine) MatchAll(r *rules.Request) (res []*rules.NetworkRule) {
	return e.AppendAllMatching(nil, r)
}

// AppendAllMatching appends all rules matching the specified request,
// regardless of the rule types, to orig.  It will find both allowlist and
// blocklist rules.  r must not be nil.
func (e *NetworkEngine) AppendAllMatching(
	orig []*rules.NetworkRule,
	r *rules.Request,
) (res []*rules.NetworkRule) {
	res = orig

	idsPtr := e.idsPool.Get()
	defer e.idsPool.Put(idsPtr)

	*idsPtr = (*idsPtr)[:0]

	*idsPtr = e.shortcutsIndex.AppendMatching(*idsPtr, r)
	*idsPtr = e.domainsIndex.AppendMatching(*idsPtr, r)

	for _, id := range *idsPtr {
		nr := e.ruleStorage.RetrieveNetworkRule(id)
		if nr != nil && nr.Match(r) {
			res = append(res, nr)
		}
	}

	for _, nr := range e.noIndex {
		if nr != nil && nr.Match(r) {
			res = append(res, nr)
		}
	}

	return res
}

// RulesCount returns the number of rules added to the engine.
func (e *NetworkEngine) RulesCount() (n uint64) {
	return e.rulesCount
}
