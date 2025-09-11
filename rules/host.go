package rules

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/AdguardTeam/urlfilter/internal/ufnet"
)

// HostRule is a structure for simple host-level rules, i.e. /etc/hosts syntax.
//
// See http://man7.org/linux/man-pages/man5/hosts.5.html.
// It also supports "just domain" syntax; in that case, the IP will be set to
// 0.0.0.0.
type HostRule struct {
	// IP is the address of the rule.
	IP netip.Addr

	// RuleText is the original text of the rule.
	RuleText string

	// Hostnames is the slice of hostnames associated with IP.
	Hostnames []string

	// FilterListID is the identifier of the filter, containing the rule.
	FilterListID int
}

// splitNextByWhitespace splits string by whitespace (' ' or '\t') and returns
// the first element.
func splitNextByWhitespace(sPtr *string) (r string) {
	s := *sPtr

	i := 0
	// Trim space.
	for ; i < len(s); i++ {
		if s[i] != ' ' && s[i] != '\t' {
			break
		}
	}

	begin := i
	// Find space or tab.
	for ; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			break
		}
	}

	r = s[begin:i]

	// Trim space.
	for ; i < len(s); i++ {
		if s[i] != ' ' && s[i] != '\t' {
			break
		}
	}

	*sPtr = s[i:]

	return r
}

// NewHostRule parses the rule and creates a new *HostRule.
func NewHostRule(ruleText string, filterListID int) (h *HostRule, err error) {
	h = &HostRule{
		RuleText:     ruleText,
		FilterListID: filterListID,
	}

	// Strip comments.
	commentIndex := strings.IndexByte(ruleText, '#')
	if commentIndex > 0 {
		ruleText = ruleText[0 : commentIndex-1]
	}

	first := splitNextByWhitespace(&ruleText)
	if len(ruleText) == 0 {
		if !ufnet.IsDomainName(first) {
			return nil, &RuleSyntaxError{
				msg:      "invalid syntax",
				ruleText: ruleText,
			}
		}

		h.Hostnames = append(h.Hostnames, first)
		h.IP = netip.IPv4Unspecified()
	} else {
		h.IP, err = netip.ParseAddr(first)
		if err != nil {
			return nil, &RuleSyntaxError{
				msg:      err.Error(),
				ruleText: ruleText,
			}
		}

		for len(ruleText) != 0 {
			host := splitNextByWhitespace(&ruleText)
			h.Hostnames = append(h.Hostnames, host)
		}
	}

	return h, nil
}

// type check
var _ Rule = (*HostRule)(nil)

// Text implements the [Rule] interface for *HostRule.
func (f *HostRule) Text() (s string) {
	return f.RuleText
}

// GetFilterListID implements the [Rule] interface for *HostRule.
func (f *HostRule) GetFilterListID() (id int) {
	return f.FilterListID
}

// String returns original rule text.
func (f *HostRule) String() (s string) {
	return f.RuleText
}

// Match returns true if this filtering rule matches the specified hostname.
func (f *HostRule) Match(hostname string) (ok bool) {
	return slices.Contains(f.Hostnames, hostname)
}
