package rules

import (
	"fmt"

	"github.com/AdguardTeam/golibs/errors"
)

const (
	// ErrTooWideRule is returned if the rule matches all URLs but has no
	// domain, denyallow, client, or ctag restrictions.
	ErrTooWideRule errors.Error = "the rule is too wide, add domain, denyallow, client, " +
		"respgeo, or ctag restrictions or make it more specific"

	// ErrUnsupportedRule signals that this might be a valid rule type, but it
	// is not yet supported by this module.
	ErrUnsupportedRule errors.Error = "this type of rules is unsupported"
)

// RuleSyntaxError represents an error while parsing a filtering rule.
//
// TODO(a.garipov):  Consider implementing [errors.Wrapper].
type RuleSyntaxError struct {
	msg      string
	ruleText string
}

// type check
var _ error = (*RuleSyntaxError)(nil)

// Error implements the error interface for *RuleSyntaxError.
func (e *RuleSyntaxError) Error() (s string) {
	return fmt.Sprintf("rule %q: %s", e.ruleText, e.msg)
}
