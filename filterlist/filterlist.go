// Package filterlist provides methods to work with filter lists.
package filterlist

import (
	"io"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/c2h5oh/datasize"
)

// StorageID is a compound identifier of a single rule.
type StorageID struct {
	listID  rules.ListID
	ruleIdx int64
}

// NewStorageID converts a pair of a [rules.ListID] and rule-list index into a
// StorageID.  ruleIdx must not be negative.
func NewStorageID(listID rules.ListID, ruleIdx int64) (id StorageID) {
	return StorageID{
		listID:  listID,
		ruleIdx: ruleIdx,
	}
}

// On Linux the size of the data block is usually 4KB.  So it makes sense to use
// 4KB.
const readerBufferSize = 4 * datasize.KB

// ErrRuleRetrieval signals that the rule cannot be retrieved by the specified
// index.
var ErrRuleRetrieval errors.Error = "cannot retrieve the rule"

// Interface represents a set of filtering rules.
type Interface interface {
	// ListID returns the rule-list identifier.
	ListID() (id rules.ListID)

	// NewScanner creates a new scanner that reads the list contents.
	NewScanner() (scanner *RuleScanner)

	// RetrieveRule returns a rule by its index.  ruleIdx must not be negative.
	RetrieveRule(ruleIdx int64) (r rules.Rule, err error)

	// SizeEstimate returns the size estimate of all rule-lists in the
	// filtering-rule list.
	SizeEstimate() (est datasize.ByteSize)

	io.Closer
}
