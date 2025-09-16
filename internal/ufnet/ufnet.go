// Package ufnet contains utilities for domain and hostname parsing/validation.
package ufnet

import (
	"strings"

	"github.com/AdguardTeam/golibs/netutil"
)

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

// IsDomainName checks if the given string is a valid domain name.  Valid domain
// name has the following syntax: [label.]... label.label.  Each label is 1 to
// 63 characters long, and may contain:
//   - ASCII letters a-z and A-Z,
//   - digits 0-9,
//   - hyphen ('-').
//
// Labels cannot start or end with hyphens (RFC 952).  Max length of ASCII
// hostname including dots is 253 characters.  TLD is greater or equal to 2
// characters.  TLD has "[a-zA-Z]+" or "xn--[a-zA-Z0-9]+" format.
//
// TODO(s.chzhen):  Consider using netutil.IsValidHostname.
// TODO(d.kolyshev):  Consider moving to golibs.
func IsDomainName(name string) (ok bool) {
	if len(name) > netutil.MaxDomainNameLen {
		return false
	}

	label, tail, found := strings.Cut(name, ".")
	for ; found; label, tail, found = strings.Cut(tail, ".") {
		if !isValidLabel(label) {
			return false
		}
	}

	return isValidTLDLabel(label)
}

const (
	// xnPrefix is the prefix of an IDNA label.
	xnPrefix = "xn--"

	// minXNLabelLen is the minimum length of an IDNA label.
	minXNLabelLen = 8
)

// isValidLabel checks if the given label is valid.  Labels must be at least 1
// character long and contain only ASCII letters, digits, and hyphens.  Labels
// cannot start or end with a hyphen.
func isValidLabel(label string) (ok bool) {
	if label == "" {
		return false
	}

	l := len(label)
	if l > netutil.MaxDomainLabelLen {
		return false
	}

	if strings.HasPrefix(label, xnPrefix) {
		if l < minXNLabelLen {
			return false
		}
	}

	return hasValidChars(label)
}

// isValidTLDLabel checks if the given label is a valid TLD.  TLDs must be a
// valid label and must be at least 2 characters long and start and end with a
// letter.
func isValidTLDLabel(label string) (ok bool) {
	if !isValidLabel(label) {
		return false
	}

	l := len(label)
	if l < 2 {
		return false
	}

	if !isLetter(label[0]) || !isLetter(label[l-1]) {
		return false
	}

	return true
}

// isLetter checks if the given character is an ASCII letter.
func isLetter(c byte) (ok bool) {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// isDigit checks if the given character is an ASCII digit.
func isDigit(c byte) (ok bool) {
	return c >= '0' && c <= '9'
}

// hasValidChars checks if the given label contains only valid characters.
func hasValidChars(label string) (ok bool) {
	for i := range label {
		c := label[i]

		if isLetter(c) || isDigit(c) {
			continue
		}

		if c != '-' {
			return false
		}

		if i == 0 || i == len(label)-1 {
			return false
		}
	}

	return true
}
