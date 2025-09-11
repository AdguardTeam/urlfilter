package filterlist

import (
	"strings"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/validate"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/c2h5oh/datasize"
)

// StringConfig represents configuration for a string-based rule list.
type StringConfig struct {
	// RulesText is a string with filtering rules (one per line).
	RulesText string

	// ID is the rule list identifier.
	ID rules.ListID

	// IgnoreCosmetic tells whether to ignore cosmetic rules or not.
	IgnoreCosmetic bool
}

// String is an [Interface] implementation which stores rules within a string.
type String struct {
	rulesText      string
	id             rules.ListID
	ignoreCosmetic bool
}

// NewString creates a new string-based rule list with the given configuration.
func NewString(conf *StringConfig) (s *String) {
	return &String{
		rulesText:      conf.RulesText,
		id:             conf.ID,
		ignoreCosmetic: conf.IgnoreCosmetic,
	}
}

// type check
var _ Interface = (*String)(nil)

// Close implements the [Interface] interface for *String.
func (s *String) Close() (err error) {
	return nil
}

// ListID implements the [Interface] interface for *String.
func (s *String) ListID() (id rules.ListID) {
	return s.id
}

// NewScanner implements the [Interface] interface for *String.
func (s *String) NewScanner() (sc *RuleScanner) {
	return NewRuleScanner(
		strings.NewReader(s.rulesText),
		s.id,
		s.ignoreCosmetic,
	)
}

// RetrieveRule implements the [Interface] interface for *String.
func (s *String) RetrieveRule(ruleIdx int64) (r rules.Rule, err error) {
	errors.Check(validate.NotNegative("ruleIdx", ruleIdx))

	if ruleIdx >= int64(len(s.rulesText)) {
		return nil, ErrRuleRetrieval
	}

	var lastIdx int64
	eolIdx := strings.IndexByte(s.rulesText[ruleIdx:], '\n')
	if eolIdx == -1 {
		lastIdx = int64(len(s.rulesText))
	} else {
		lastIdx = ruleIdx + int64(eolIdx)
	}

	line := strings.TrimSpace(s.rulesText[ruleIdx:lastIdx])
	if len(line) == 0 {
		return nil, ErrRuleRetrieval
	}

	return rules.NewRule(line, s.id)
}

// SizeEstimate implements the [Interface] interface for *String.
func (s *String) SizeEstimate() (est datasize.ByteSize) {
	return datasize.ByteSize(len(s.rulesText))
}
