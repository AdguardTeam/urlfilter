// Package rules contains implementation of several kinds of blocking rules.
package rules

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// isCosmetic returns true if line is a cosmetic filtering rule.
func isCosmetic(line string) (ok bool) {
	index, _ := findCosmeticRuleMarker(line)

	return index != -1
}

// isDomainOrSubdomainOfAny returns true if domains contain domain itself or its
// superdomain.  It supports wildcards.
//
// TODO(a.garipov):  Test and refactor.
func isDomainOrSubdomainOfAny(domain string, domains []string) (ok bool) {
	for _, d := range domains {
		if strings.HasSuffix(d, ".*") {
			// A pattern like "google.*" will match any "google.TLD" domain or
			// subdomain.
			withoutWildcard := d[0 : len(d)-1]

			if strings.HasPrefix(domain, withoutWildcard) ||
				(strings.Index(domain, withoutWildcard) > 0 && strings.Index(domain, "."+withoutWildcard) > 0) {
				tld, icann := publicsuffix.PublicSuffix(domain)

				// Check that the domain's TLD is one of the public suffixes.
				if tld != "" && icann && strings.HasSuffix(domain, withoutWildcard+tld) {
					return true
				}
			}
		} else {
			if domain == d ||
				(strings.HasSuffix(domain, d) && strings.HasSuffix(domain, "."+d)) {
				return true
			}
		}
	}

	return false
}

// splitWithEscapeCharacter splits s by sep if it is not escaped.
//
// TODO(a.garipov):  Refactor.
func splitWithEscapeCharacter(s string, sep, esc byte, preserveAllTokens bool) (parts []string) {
	if s == "" {
		return parts
	}

	var sb strings.Builder
	escaped := false
	for i := range s {
		c := s[i]

		switch c {
		case esc:
			escaped = true
		case sep:
			if escaped {
				_ = sb.WriteByte(c)
				escaped = false
			} else {
				if preserveAllTokens || sb.Len() > 0 {
					parts = append(parts, sb.String())
					sb.Reset()
				}
			}
		default:
			if escaped {
				escaped = false
				_ = sb.WriteByte(esc)
			}

			_ = sb.WriteByte(c)
		}
	}

	if preserveAllTokens || sb.Len() > 0 {
		parts = append(parts, sb.String())
	}

	return parts
}
