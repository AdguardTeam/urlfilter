// Package ufnet contains utilities for domain and hostname parsing/validation.
package ufnet

import "strings"

// ExtractHostname quickly retrieves hostname from the given URL.
//
// NOTE: ExtractHostname is an optimized, best-effort function to retrieve a
// hostname from a URL-like string.  The result is not guaranteed to be correct
// for some edge cases, which include non-hierarchical URLs and IPv6 hostnames.
//
// TODO(a.garipov): Consider moving to golibs.
//
// TODO(s.chzhen):  Consider using url.URL.
func ExtractHostname(url string) (hostname string) {
	firstIdx := strings.Index(url, "//")
	if firstIdx == -1 {
		// This is a non-hierarchical structured URL (e.g. stun: or turn:)
		// https://tools.ietf.org/html/rfc4395#section-2.2
		// https://datatracker.ietf.org/doc/html/rfc7064#appendix-B
		firstIdx = strings.Index(url, ":")
		if firstIdx == -1 {
			return ""
		}

		firstIdx = firstIdx - 1
	} else {
		firstIdx = firstIdx + 2
	}

	if firstIdx < 0 {
		return ""
	}

	nextIdx := strings.IndexAny(url[firstIdx:], "/:?")
	if nextIdx == -1 {
		nextIdx = len(url)
	} else {
		nextIdx += firstIdx
	}

	if nextIdx <= firstIdx {
		return ""
	}

	return url[firstIdx:nextIdx]
}

// IsDomainName - check if input string is a valid domain name
// Syntax: [label.]... label.label
//
// Each label is 1 to 63 characters long, and may contain:
//
//	. ASCII letters a-z and A-Z
//	. digits 0-9
//	. hyphen ('-')
//
// . labels cannot start or end with hyphens (RFC 952)
// . max length of ascii hostname including dots is 253 characters
// . TLD is >=2 characters
// . TLD is [a-zA-Z]+ or "xn--[a-zA-Z0-9]+"
//
// TODO(s.chzhen):  Consider using netutil.IsValidHostname.
//
//nolint:gocyclo
func IsDomainName(name string) (ok bool) {
	if len(name) > 253 {
		return false
	}

	st := 0
	nLabel := 0
	nLevel := 1
	var prevChar byte
	charOnly := true
	xn := 0

	for _, c := range []byte(name) {
		switch st {
		case 0:
			fallthrough
		case 1:
			if !((c >= 'a' && c <= 'z') ||
				(c >= 'A' && c <= 'Z')) {
				charOnly = false

				if !(c >= '0' && c <= '9') {
					return false
				}
			} else if c == 'x' || c == 'X' {
				xn = 1
			}
			st = 2
			nLabel = 1

		case 2:
			if c == '.' {
				if prevChar == '-' {
					return false
				}

				nLevel++
				st = 0
				charOnly = true
				xn = 0

				continue
			}

			if nLabel == 63 {
				return false
			}

			if !((c >= 'a' && c <= 'z') ||
				(c >= 'A' && c <= 'Z')) {
				charOnly = false
				if !((c >= '0' && c <= '9') ||
					c == '-') {

					return false
				}
			}

			if xn > 0 {
				if xn < len("xn--") {
					if c == "xn--"[xn] {
						xn++
					} else {
						xn = 0
					}
				} else {
					xn++
				}
			}

			prevChar = c
			nLabel++
		}
	}

	if st != 2 ||
		nLabel == 1 ||
		(!charOnly && xn < len("xn--wwww")) {

		return false
	}

	return true
}
