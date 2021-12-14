package filterutil

import "net"

// ParseIP parses the string and checks if it's a valid IP address or not.  It
// uses net.ParseIP internally and the purpose of this wrapper is to first do a
// quick check without additional allocations.
func ParseIP(s string) (ip net.IP) {
	for _, c := range s {
		if c != '.' && c != ':' &&
			(c < '0' || c > '9') &&
			(c < 'A' || c > 'F') &&
			(c < 'a' || c > 'f') &&
			c != '[' && c != ']' {
			return nil
		}
	}

	return net.ParseIP(s)
}
