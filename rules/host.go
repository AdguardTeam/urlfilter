package rules

import (
	"net/netip"
	"strings"

	"github.com/AdguardTeam/urlfilter/filterutil"
)

// HostRule is a structure for simple host-level rules (i.e. /etc/hosts syntax).
// http://man7.org/linux/man-pages/man5/hosts.5.html
// It also supports "just domain" syntax. In this case, the IP will be set to 0.0.0.0.
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

// Split string by whitespace (' ' or '\t') and return the first element
func splitNextByWhitespace(ps *string) string {
	s := *ps

	i := 0
	// trim space
	for ; i < len(s); i++ {
		if !(s[i] == ' ' || s[i] == '\t') {
			break
		}
	}

	begin := i
	// find space or tab
	for ; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			break
		}
	}

	r := s[begin:i]

	// trim space
	for ; i < len(s); i++ {
		if !(s[i] == ' ' || s[i] == '\t') {
			break
		}
	}
	*ps = s[i:]

	return r
}

// NewHostRule parses the rule and creates a new HostRule instance
// The format is:
// IP_address canonical_hostname [aliases...]
func NewHostRule(ruleText string, filterListID int) (h *HostRule, err error) {
	h = &HostRule{
		RuleText:     ruleText,
		FilterListID: filterListID,
	}

	// Strip comment
	commentIndex := strings.IndexByte(ruleText, '#')
	if commentIndex > 0 {
		ruleText = ruleText[0 : commentIndex-1]
	}

	first := splitNextByWhitespace(&ruleText)
	if len(ruleText) == 0 {
		if !filterutil.IsDomainName(first) {
			return nil, &RuleSyntaxError{msg: "invalid syntax", ruleText: ruleText}
		}

		h.Hostnames = append(h.Hostnames, first)
		h.IP = netip.IPv4Unspecified()

	} else {
		h.IP, err = netip.ParseAddr(first)
		if err != nil {
			return nil, &RuleSyntaxError{msg: err.Error(), ruleText: ruleText}
		}

		for len(ruleText) != 0 {
			host := splitNextByWhitespace(&ruleText)
			h.Hostnames = append(h.Hostnames, host)
		}
	}

	return h, nil
}

// Text returns the original rule text
// Implements the `Rule` interface
func (f *HostRule) Text() string {
	return f.RuleText
}

// GetFilterListID returns ID of the filter list this rule belongs to
func (f *HostRule) GetFilterListID() int {
	return f.FilterListID
}

// String returns original rule text
func (f *HostRule) String() string {
	return f.RuleText
}

// Match checks if this filtering rule matches the specified hostname
func (f *HostRule) Match(hostname string) bool {
	if len(f.Hostnames) == 1 && hostname == f.Hostnames[0] {
		return true
	}

	for _, h := range f.Hostnames {
		if h == hostname {
			return true
		}
	}

	return false
}
