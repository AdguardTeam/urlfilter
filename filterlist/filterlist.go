// Package filterlist provides methods to work with filter lists.
package filterlist

import (
	"io"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/c2h5oh/datasize"
)

// On Linux the size of the data block is usually 4KiB.  So it makes sense to
// use 4KiB.
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
