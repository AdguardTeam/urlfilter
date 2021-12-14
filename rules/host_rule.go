package rules

import (
	"net"
	"strings"

	"github.com/AdguardTeam/urlfilter/filterutil"
)

// HostRule is a structure for simple host-level rules (i.e. /etc/hosts syntax).
// http://man7.org/linux/man-pages/man5/hosts.5.html
// It also supports "just domain" syntax. In this case, the IP will be set to 0.0.0.0.
type HostRule struct {
	RuleText     string   // RuleText is the original rule text
	FilterListID int      // Filter list identifier
	Hostnames    []string // Hostnames is the list of hostnames that is configured
	IP           net.IP   // ip address
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
func NewHostRule(ruleText string, filterListID int) (*HostRule, error) {
	h := HostRule{
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
		h.IP = net.IPv4(0, 0, 0, 0)

	} else {
		h.IP = filterutil.ParseIP(first)
		if h.IP == nil {
			return nil, &RuleSyntaxError{msg: "cannot parse IP", ruleText: ruleText}
		}
		for len(ruleText) != 0 {
			host := splitNextByWhitespace(&ruleText)
			h.Hostnames = append(h.Hostnames, host)
		}
	}

	return &h, nil
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
