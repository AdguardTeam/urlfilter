package rules

import (
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// findSorted - finds value in a sorted array
// returns value index or -1 if nothing found
func findSorted(sortedArray []string, val string) int {
	i := sort.SearchStrings(sortedArray, val)
	if i == len(sortedArray) || sortedArray[i] != val {
		return -1
	}
	return i
}

// splitWithEscapeCharacter splits string by the specified separator if it is not escaped
func splitWithEscapeCharacter(str string, sep, escapeCharacter byte, preserveAllTokens bool) []string {
	parts := make([]string, 0)

	if str == "" {
		return parts
	}

	var sb strings.Builder
	escaped := false
	for i := range str {
		c := str[i]

		if c == escapeCharacter {
			escaped = true
		} else if c == sep {
			if escaped {
				sb.WriteByte(c)
				escaped = false
			} else {
				if preserveAllTokens || sb.Len() > 0 {
					parts = append(parts, sb.String())
					sb.Reset()
				}
			}
		} else {
			if escaped {
				escaped = false
				sb.WriteByte(escapeCharacter)
			}
			sb.WriteByte(c)
		}
	}

	if preserveAllTokens || sb.Len() > 0 {
		parts = append(parts, sb.String())
	}

	return parts
}

// stringArraysEquals checks if arrays are equal
func stringArraysEquals(l, r []string) bool {
	if len(l) != len(r) {
		return false
	}

	for i := range l {
		if l[i] != r[i] {
			return false
		}
	}

	return true
}

// isDomainOrSubdomainOfAny checks if "domain" is domain or subdomain or any of the "domains"
func isDomainOrSubdomainOfAny(domain string, domains []string) bool {
	for _, d := range domains {
		if strings.HasSuffix(d, ".*") {
			// A pattern like "google.*" will match any "google.TLD" domain or subdomain
			withoutWildcard := d[0 : len(d)-1]

			if strings.HasPrefix(domain, withoutWildcard) ||
				(strings.Index(domain, withoutWildcard) > 0 &&
					strings.Index(domain, "."+withoutWildcard) > 0) {
				tld, icann := publicsuffix.PublicSuffix(domain)

				// Let's check that the domain's TLD is one of the public suffixes
				if tld != "" && icann &&
					strings.HasSuffix(domain, withoutWildcard+tld) {
					return true
				}
			}
		} else {
			if domain == d ||
				(strings.HasSuffix(domain, d) &&
					strings.HasSuffix(domain, "."+d)) {
				return true
			}
		}
	}
	return false
}

// sort.Interface
type byLength []string

func (s byLength) Len() int {
	return len(s)
}

func (s byLength) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s byLength) Less(i, j int) bool {
	return len(s[i]) < len(s[j])
}
