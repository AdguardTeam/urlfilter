package filterlist

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/c2h5oh/datasize"
)

// RuleStorage is an abstraction that combines several rule lists.  It can be
// scanned using a [RuleStorageScanner], and also it allows retrieving rules by
// its index.
//
// The idea is to keep rules in a serialized format (even original format in the
// case of [File]) and create them in a lazy manner only when we really need
// them.  When the filtering engine is being initialized, we need to scan the
// rule lists once in order to fill up the lookup tables.  We use rule indexes
// as a unique rule identifier instead of the rule itself.  The rule is created
// (see [RuleStorage.RetrieveRule]) only when there's a chance that it's needed.
type RuleStorage struct {
	// cache with the rules which were retrieved.  The key is the storage index
	// and the value is the rule.  cache can be nil only in tests.
	//
	// TODO(a.garipov):  Use syncutil.Map.
	cache *sync.Map

	// listsMap is a map with rule lists.  map key is the list ID.
	//
	// TODO(a.garipov):  Consider using an ID-to-index mapping bound to lists
	// below.
	listsMap map[rules.ListID]Interface

	// lists is an array of rules lists which can be accessed using this
	// RuleStorage.
	lists []Interface

	// sizeEst is the size estimate of all rule-lists in the storage.
	sizeEst datasize.ByteSize
}

// NewRuleStorage creates a new instance of the [*RuleStorage] and validates the
// list of rules specified.
func NewRuleStorage(lists []Interface) (s *RuleStorage, err error) {
	var sizeEst datasize.ByteSize
	listsMap := make(map[rules.ListID]Interface, len(lists))
	for i, l := range lists {
		id := l.ListID()
		if _, ok := listsMap[id]; ok {
			return nil, fmt.Errorf("at index %d: id: %w: %d", i, errors.ErrDuplicated, id)
		}

		listsMap[id] = l
		sizeEst += l.SizeEstimate()
	}

	return &RuleStorage{
		cache:    &sync.Map{},
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

// RetrieveRule looks for the filtering rule in this storage.  id is the storage
// ID as received from the scanner.
func (s *RuleStorage) RetrieveRule(id StorageID) (r rules.Rule, err error) {
	if s.cache != nil {
		ruleVal, ok := s.cache.Load(id)
		if ok {
			return ruleVal.(rules.Rule), nil
		}
	}

	list, ok := s.listsMap[id.listID]
	if !ok {
		return nil, fmt.Errorf("list %d does not exist", id.listID)
	}

	r, err = list.RetrieveRule(id.ruleIdx)
	if r != nil && s.cache != nil {
		s.cache.Store(id, r)
	}

	return r, err
}

// RetrieveNetworkRule is a helper method that retrieves a network rule from the
// storage.  It returns a pointer to the rule or nil in any other case (not
// found or error).
//
// TODO(a.garipov):  Rewrite into a helper function instead of a method and
// return the error.
func (s *RuleStorage) RetrieveNetworkRule(id StorageID) (nr *rules.NetworkRule) {
	r, err := s.RetrieveRule(id)
	if err != nil {
		// TODO(a.garipov):  Add better support for log/slog.
		slog.Error("cannot retrieve network rule", "id", id, slogutil.KeyError, err)

		return nil
	}

	nr, _ = r.(*rules.NetworkRule)

	return nr
}

// RetrieveHostRule is a helper method that retrieves a host rule from the
// storage.  It returns a pointer to the rule or nil in any other case (not
// found or error).
//
// TODO(a.garipov):  Rewrite into a helper function instead of a method and
// return the error.
func (s *RuleStorage) RetrieveHostRule(id StorageID) (hr *rules.HostRule) {
	r, err := s.RetrieveRule(id)
	if err != nil {
		// TODO(a.garipov):  Add better support for log/slog.
		slog.Error("cannot retrieve host rule", "id", id, slogutil.KeyError, err)

		return nil
	}

	hr, _ = r.(*rules.HostRule)

	return hr
}

// SizeEstimate returns the size estimate of all rule-lists in the storage.
func (s *RuleStorage) SizeEstimate() (est datasize.ByteSize) {
	return s.sizeEst
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
