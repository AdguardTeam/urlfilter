package filterlist

import (
	"bytes"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/validate"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/c2h5oh/datasize"
)

// BytesConfig represents configuration for a bytes-based rule list.
type BytesConfig struct {
	// RulesText is the slice of bytes containing rules, each rule is separated
	// by a newline.  It must not be modified after calling [NewBytes].
	RulesText []byte

	// ID is the rule list identifier.
	ID rules.ListID

	// IgnoreCosmetic tells whether to ignore cosmetic rules or not.
	IgnoreCosmetic bool
}

// Bytes is an [Interface] implementation which stores rules within a byte
// slice.
type Bytes struct {
	rulesText      []byte
	id             rules.ListID
	ignoreCosmetic bool
}

// NewBytes creates a new bytes-based rule list with the given configuration.
func NewBytes(conf *BytesConfig) (s *Bytes) {
	return &Bytes{
		id:             conf.ID,
		rulesText:      conf.RulesText,
		ignoreCosmetic: conf.IgnoreCosmetic,
	}
}

// type check
var _ Interface = (*Bytes)(nil)

// Close implements the [Interface] interface for *Bytes.
func (b *Bytes) Close() (err error) {
	return nil
}

// ListID implements the [Interface] interface for *Bytes.
func (b *Bytes) ListID() (id rules.ListID) {
	return b.id
}

// NewScanner implements the [Interface] interface for *Bytes.
func (b *Bytes) NewScanner() (sc *RuleScanner) {
	return NewRuleScanner(bytes.NewReader(b.rulesText), b.id, b.ignoreCosmetic)
}

// RetrieveRule implements the [Interface] interface for *Bytes.
func (b *Bytes) RetrieveRule(ruleIdx int64) (r rules.Rule, err error) {
	errors.Check(validate.NotNegative("ruleIdx", ruleIdx))

	if ruleIdx >= int64(len(b.rulesText)) {
		return nil, ErrRuleRetrieval
	}

	var lastIdx int64
	eolIdx := bytes.IndexByte(b.rulesText[ruleIdx:], '\n')
	if eolIdx == -1 {
		lastIdx = int64(len(b.rulesText))
	} else {
		lastIdx = ruleIdx + int64(eolIdx)
	}

	line := bytes.TrimSpace(b.rulesText[ruleIdx:lastIdx])
	if len(line) == 0 {
		return nil, ErrRuleRetrieval
	}

	return rules.NewRule(string(line), b.id)
}

// SizeEstimate implements the [Interface] interface for *Bytes.
func (b *Bytes) SizeEstimate() (est datasize.ByteSize) {
	return datasize.ByteSize(len(b.rulesText))
}
