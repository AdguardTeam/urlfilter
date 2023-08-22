package filterutil

// isAddrRune returns true if r is a valid rune of string representation of an
// IP address.
func isAddrRune(r rune) (ok bool) {
	switch {
	case r == '.', r == ':',
		r >= '0' && r <= '9',
		r >= 'A' && r <= 'F',
		r >= 'a' && r <= 'f',
		r == '[', r == ']':
		return true
	default:
		return false
	}
}

// IsProbablyIP returns true if s only contains characters that can be part of
// an IP address.  It's needed to avoid unnecessary allocations when parsing
// with [netip.ParseAddr].
func IsProbablyIP(s string) (ok bool) {
	for _, r := range s {
		if !isAddrRune(r) {
			return false
		}
	}

	return len(s) >= len("::")
}
