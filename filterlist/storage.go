package filterlist

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/urlfilter/rules"
)

// RuleStorage is an abstraction that combines several rule lists It can be
// scanned using a [RuleStorageScanner], and also it allows retrieving rules by
// its index
//
// The idea is to keep rules in a serialized format (even original format in the
// case of [FileRuleList]) and create them in a lazy manner only when we really
// need them.  When the filtering engine is being initialized, we need to scan
// the rule lists once in order to fill up the lookup tables.  We use rule
// indexes as a unique rule identifier instead of the rule itself.  The rule is
// created (see [RuleStorage.RetrieveRule]) only when there's a chance that it's
// needed.
//
// Rule index is an int64 value that actually consists of two int32 values: one
// is the rule list identifier, and the second is the index of the rule inside
// of that list.
type RuleStorage struct {
	// cacheMu protects cache.
	cacheMu *sync.RWMutex

	// cache with the rules which were retrieved.
	cache map[int64]rules.Rule

	// listsMap is a map with rule lists.  map key is the list ID.
	listsMap map[int]RuleList

	// lists is an array of rules lists which can be accessed
	// using this RuleStorage
	lists []RuleList
}

// NewRuleStorage creates a new instance of the RuleStorage and validates the
// list of rules specified.
func NewRuleStorage(lists []RuleList) (s *RuleStorage, err error) {
	if lists == nil {
		lists = make([]RuleList, 0)
	}

	listsMap := make(map[int]RuleList, len(lists))
	for i, list := range lists {
		id := list.GetID()
		if _, ok := listsMap[id]; ok {
			return nil, fmt.Errorf("list at index %d: duplicate list id: %d", i, id)
		}

		listsMap[id] = list
	}

	return &RuleStorage{
		cacheMu:  &sync.RWMutex{},
		cache:    map[int64]rules.Rule{},
		listsMap: listsMap,
		lists:    lists,
	}, nil
}

// NewRuleStorageScanner creates a new instance of RuleStorageScanner.  It can
// be used to read and parse all the storage contents.
func (s *RuleStorage) NewRuleStorageScanner() (sc *RuleStorageScanner) {
	var scanners []*RuleScanner
	for _, list := range s.lists {
		scanner := list.NewScanner()
		scanners = append(scanners, scanner)
	}

	return &RuleStorageScanner{
		Scanners: scanners,
	}
}

// RetrieveRule looks for the filtering rule in this storage.  storageIdx is the
// lookup index that you can get from the rule storage scanner.
func (s *RuleStorage) RetrieveRule(storageIdx int64) (r rules.Rule, err error) {
	var ok bool
	func() {
		s.cacheMu.RLock()
		defer s.cacheMu.RUnlock()

		r, ok = s.cache[storageIdx]
	}()
	if ok {
		return r, nil
	}

	listID, ruleIdx := storageIdxToRuleListIdx(storageIdx)

	list, ok := s.listsMap[int(listID)]
	if !ok {
		return nil, fmt.Errorf("list %d does not exist", listID)
	}

	r, err = list.RetrieveRule(int(ruleIdx))
	if r != nil {
		func() {
			s.cacheMu.Lock()
			defer s.cacheMu.Unlock()

			s.cache[storageIdx] = r
		}()
	}

	return r, err
}

// RetrieveNetworkRule is a helper method that retrieves a network rule from the
// storage.  It returns a pointer to the rule or nil in any other case (not
// found or error).
func (s *RuleStorage) RetrieveNetworkRule(idx int64) (nr *rules.NetworkRule) {
	r, err := s.RetrieveRule(idx)
	if err != nil {
		// TODO(a.garipov):  Add better support for log/slog.
		slog.Error("cannot retrieve network rule", "idx", idx, slogutil.KeyError, err)

		return nil
	}

	nr, _ = r.(*rules.NetworkRule)

	return nr
}

// RetrieveHostRule is a helper method that retrieves a host rule from the
// storage.  It returns a pointer to the rule or nil in any other case (not
// found or error).
func (s *RuleStorage) RetrieveHostRule(idx int64) (hr *rules.HostRule) {
	r, err := s.RetrieveRule(idx)
	if err != nil {
		// TODO(a.garipov):  Add better support for log/slog.
		slog.Error("cannot retrieve host rule", "idx", idx, slogutil.KeyError, err)

		return nil
	}

	hr, _ = r.(*rules.HostRule)

	return hr
}

// Close closes the storage instance.
func (s *RuleStorage) Close() (err error) {
	if len(s.lists) == 0 {
		return nil
	}

	var errs []error
	for _, l := range s.lists {
		err = l.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Annotate(errors.Join(errs...), "closing rule lists: %w")
}

// GetCacheSize returns the size of the in-memory rules cache.
func (s *RuleStorage) GetCacheSize() (sz int) {
	return len(s.cache)
}
