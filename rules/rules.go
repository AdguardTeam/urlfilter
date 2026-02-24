// Package rules contains implementation of all kinds of blocking rules.
package rules

import (
	"strings"

	"github.com/AdguardTeam/golibs/netutil"
	"golang.org/x/net/publicsuffix"
)

// ListID is the unique ID of a filtering-rule list.
//
// TODO(a.garipov):  See if there are better types for this.  Currently, it is a
// uint64 to make it possible to use maphash and the similar hashing functions
// and also for performance reasons.
type ListID uint64

// isCosmetic returns true if line is a cosmetic filtering rule.
func isCosmetic(line string) (ok bool) {
	index, _ := findCosmeticRuleMarker(line)

	return index != -1
}

// isDomainOrSubdomainOfAny returns true if domains contain domain itself or its
// superdomain.  It supports wildcards.
func isDomainOrSubdomainOfAny(domain string, domains []string) (ok bool) {
	for _, d := range domains {
		if matchWildcard(domain, d) {
			return true
		}

		if domain == d || netutil.IsSubdomain(domain, d) {
			return true
		}
	}

	return false
}

// matchWildcard matches the domain against a wildcard pattern with TLD
// placeholder.  The wildcard must appear as a complete domain label before a
// valid top-level domain.  For example, "example.*" matches "example.com" and
// "sub.example.org", but not "not-example.com" (not a separate label) or
// "example.sub.com" ("sub.com" is not a valid public suffix).
func matchWildcard(domain, wildcard string) (ok bool) {
	if !strings.HasSuffix(wildcard, ".*") {
		return false
	}
	// A pattern like "google.*" will match any "google.TLD" domain or
	// subdomain.
	withoutWildcard := wildcard[0 : len(wildcard)-1]

	// Unlike [netutil.IsSubdomain], which requires the pattern to be a suffix
	// of the domain, this check matches the wildcard pattern at any position
	// within the domain hierarchy.
	if strings.HasPrefix(domain, withoutWildcard) ||
		(strings.Index(domain, withoutWildcard) > 0 && strings.Index(domain, "."+withoutWildcard) > 0) {
		tld, icann := publicsuffix.PublicSuffix(domain)

		// Check that the domain's TLD is one of the public suffixes.
		if tld != "" && icann && strings.HasSuffix(domain, withoutWildcard+tld) {
			return true
		}
	}

	return false
}

// splitWithEscapeCharacter splits s by sep if it is not escaped.
func splitWithEscapeCharacter(s string, sep, esc byte) (parts []string) {
	sb := strings.Builder{}
	l := len(s)

	for i := 0; i < l; i++ {
		ch := s[i]

		if ch == esc && i+1 < l && s[i+1] == sep {
			sb.WriteByte(sep)
			i++
		} else if ch == sep {
			if sb.Len() > 0 {
				parts = append(parts, sb.String())
				sb.Reset()
			}
		} else {
			sb.WriteByte(ch)
		}
	}

	if sb.Len() > 0 {
		parts = append(parts, sb.String())
	}

	return parts
}
