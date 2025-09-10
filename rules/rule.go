package rules

import (
	"fmt"
	"slices"
	"strings"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/urlfilter/internal/ufnet"
	"github.com/miekg/dns"
)

// RuleSyntaxError represents an error while parsing a filtering rule.
//
// TODO(a.garipov):  Consider making unwrappable.
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

// ErrUnsupportedRule signals that this might be a valid rule type, but it is
// not yet supported by this library
var ErrUnsupportedRule errors.Error = "this type of rules is unsupported"

// Rule is a base interface for all filtering rules
type Rule interface {
	// Text returns the original rule text
	Text() string

	// GetFilterListID returns ID of the filter list this rule belongs to
	GetFilterListID() int
}

// NewRule creates a new filtering rule from the specified line.  It returns nil
// if the line is empty or if it is a comment.
func NewRule(line string, filterListID int) (r Rule, err error) {
	if line = strings.TrimSpace(line); line == "" || isComment(line) {
		return nil, nil
	}

	if isCosmetic(line) {
		return NewCosmeticRule(line, filterListID)
	}

	var f *HostRule
	if f, err = NewHostRule(line, filterListID); err == nil {
		return f, nil
	}

	return NewNetworkRule(line, filterListID)
}

// isComment checks if the line is a comment
func isComment(line string) bool {
	if len(line) == 0 {
		return false
	}

	if line[0] == '!' {
		return true
	}

	if line[0] == '#' {
		if len(line) == 1 {
			return true
		}

		// Now we should check that this is not a cosmetic rule
		for _, marker := range cosmeticRulesMarkers {
			if startsAtIndexWith(line, 0, marker) {
				return false
			}
		}

		return true
	}

	return false
}

// parseDomains parses the $domain modifier or cosmetic rules domains.  sep is
// the separator character.  For network rules it is '|'; for cosmetic, ','.
func parseDomains(domains, sep string) (permittedDomains, restrictedDomains []string, err error) {
	if domains == "" {
		// TODO(a.garipov):  Here and in the whole package, use the standard
		// error values.
		return nil, nil, errors.Error("no domains specified")
	}

	list := strings.Split(domains, sep)
	for i := range list {
		d := list[i]
		restricted := false
		if strings.HasPrefix(d, "~") {
			restricted = true
			d = d[1:]
		}

		if !ufnet.IsDomainName(d) && !strings.HasSuffix(d, ".*") {
			err = fmt.Errorf("invalid domain specified: %s", domains)

			return permittedDomains, restrictedDomains, err
		}

		if restricted {
			restrictedDomains = append(restrictedDomains, d)
		} else {
			permittedDomains = append(permittedDomains, d)
		}
	}

	return permittedDomains, restrictedDomains, nil
}

// strToRRType converts s to a DNS resource record (RR) type.  s may be in any
// letter case.
func strToRRType(s string) (rr RRType, err error) {
	// TypeNone and TypeReserved are special cases in package dns.
	if strings.EqualFold(s, "none") || strings.EqualFold(s, "reserved") {
		return 0, errors.Error("dns rr type is none or reserved")
	}

	rr, ok := dns.StringToType[strings.ToUpper(s)]
	if !ok {
		return 0, fmt.Errorf("dns rr type %q is invalid", s)
	}

	return rr, nil
}

// parseDNSTypes parses the $dnstype modifier.  types is the list of types.
func parseDNSTypes(types string) (permittedTypes, restrictedTypes []RRType, err error) {
	if types == "" {
		return nil, nil, errors.Error("no dns record types specified")
	}

	list := strings.Split(types, "|")
	for i, rrStr := range list {
		if len(rrStr) == 0 {
			return nil, nil, fmt.Errorf("dns record type %d is empty", i)
		}

		restricted := rrStr[0] == '~'
		if restricted {
			rrStr = rrStr[1:]
		}

		var rr RRType
		rr, err = strToRRType(rrStr)
		if err != nil {
			return nil, nil, fmt.Errorf("type %d (%q): %w", i, rrStr, err)
		}

		if restricted {
			restrictedTypes = append(restrictedTypes, rr)
		} else {
			permittedTypes = append(permittedTypes, rr)
		}
	}

	return permittedTypes, restrictedTypes, nil
}

// isValidCTag - returns TRUE if ctag value format is correct: a-z0-9_
func isValidCTag(s string) bool {
	for _, ch := range s {
		if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '_' {
			return false
		}
	}

	return true
}

// parseCTags parses tags from the $ctag modifier.  sep is the separator
// character; for network rules it is '|'.  permittedCTags and restrictedCTags
// are sorted.
func parseCTags(value, sep string) (permittedCTags, restrictedCTags []string, err error) {
	if value == "" {
		return nil, nil, errors.Error("value is empty")
	}

	list := strings.Split(value, sep)
	for i := range list {
		d := list[i]
		restricted := false
		if strings.HasPrefix(d, "~") {
			restricted = true
			d = d[1:]
		}

		if !isValidCTag(d) {
			return permittedCTags, restrictedCTags, fmt.Errorf("invalid ctag specified: %q", value)
		}

		if restricted {
			restrictedCTags = append(restrictedCTags, d)
		} else {
			permittedCTags = append(permittedCTags, d)
		}
	}

	// Sorting tags so that we could use binary search
	slices.Sort(permittedCTags)
	slices.Sort(restrictedCTags)

	return permittedCTags, restrictedCTags, nil
}

// The $client modifier allows specifying clients this rule will be working for.
// It accepts client names, IP addresses, or CIDR address ranges.
//
// The syntax is:
//
// $client=value1|value2|...
// You can also specify "restricted" clients by adding a ~ character before the client IP or name.
// In this case, the rule will not be applied to this client's requests.
//
// $client=~value1
//
// ## Specifying client names
// Client names usually contain spaces or other special characters, that's why you
// should enclose the name in quotes (both double-quotes and single-quotes are supported).
// If the client name contains quotes, use `\` to escape them.
// Also, you need to escape commas (`,`) and pipes (`|`).
//
// Please note, that when specifying a "restricted" client, you must keep `~` out of the quotes.
//
// Examples of the input value:
// 127.0.0.1
// 192.168.3.0/24
// ::
// fe01::/64
// 'Frank\'s laptop'
// "Frank's phone"
// ~'Mary\'s\, John\'s\, and Boris\'s laptops'
// ~Mom|~Dad|"Kids"
//
// Returns sorted arrays of permitted and restricted clients.
//
// TODO(a.garipov):  Improve the documentation.
func parseClients(value string, sep byte) (permitted, restricted *clients, err error) {
	if value == "" {
		return nil, nil, errors.Error("value is empty")
	}

	// First of all, split by the specified separator
	list := splitWithEscapeCharacter(value, sep, '\\', false)
	for _, s := range list {
		isRestricted := false
		client := s

		// 1. Check if this is a restricted or permitted client
		if strings.HasPrefix(client, "~") {
			isRestricted = true
			client = client[1:]
		}

		// 2. Check if quoted
		quoteChar := uint8(0)
		if len(client) >= 2 &&
			(client[0] == '\'' || client[0] == '"') &&
			client[0] == client[len(client)-1] {
			quoteChar = client[0]
		}

		// 3. If quoted, remove quotes
		if quoteChar > 0 {
			client = client[1 : len(client)-1]
		}

		// 4. Unescape commas and quotes
		client = strings.ReplaceAll(client, "\\,", ",")
		if quoteChar > 0 {
			client = strings.ReplaceAll(client, "\\"+string(quoteChar), string(quoteChar))
		}

		if client == "" {
			return nil, nil, fmt.Errorf("invalid $client value %q", value)
		}

		if isRestricted {
			if restricted == nil {
				restricted = &clients{}
			}
			restricted.add(client)
		} else {
			if permitted == nil {
				permitted = &clients{}
			}
			permitted.add(client)
		}
	}

	permitted.finalize()
	restricted.finalize()

	return permitted, restricted, nil
}
