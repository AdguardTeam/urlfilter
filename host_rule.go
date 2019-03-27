package urlfilter

import (
	"fmt"
	"net"
	"strings"
)

// HostRule is a structure for simple host-level rules (i.e. /etc/hosts syntax).
// http://man7.org/linux/man-pages/man5/hosts.5.html
type HostRule struct {
	RuleText     string   // RuleText is the original rule text
	FilterListID int      // Filter list identifier
	Hostnames    []string // Hostnames is the list of hostnames that is configured
	IP           net.IP   // ip address
}

// NewHostRule parses the rule and creates a new HostRule instance
// The format is:
// IP_address canonical_hostname [aliases...]
func NewHostRule(ruleText string, filterListID int) (*HostRule, error) {
	h := HostRule{
		RuleText:     ruleText,
		FilterListID: filterListID,
	}

	parts := strings.Fields(strings.TrimSpace(ruleText))
	if len(parts) < 2 {
		return nil, fmt.Errorf("cannot parse host rule %s", ruleText)
	}

	var ip net.IP
	var hostnames []string
	for i, part := range parts {
		if i == 0 {
			ip = net.ParseIP(parts[0])
			if ip == nil {
				return nil, fmt.Errorf("cannot parse the IP address from %s", ruleText)
			}
		} else {
			hostnames = append(hostnames, part)
		}
	}

	h.Hostnames = hostnames
	h.IP = ip
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
