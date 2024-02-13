package rules

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/AdguardTeam/urlfilter/filterutil"
)

// clients is a set representation for $client modifier.
type clients struct {
	// hosts are the clients not within nets slice.
	hosts []string

	// nets are the clients defined by IP addresses or subnets.
	nets []netip.Prefix
}

// Len returns the number of specified identifiers.
func (c *clients) Len() int {
	if c == nil {
		return 0
	}

	return len(c.hosts) + len(c.nets)
}

// Equal returns true if c and other contain the same identifiers.
func (c *clients) Equal(other *clients) (ok bool) {
	switch {
	case c == nil:
		return other == nil
	case
		other == nil,
		!slices.Equal(c.hosts, other.hosts),
		!slices.Equal(c.nets, other.nets):
		return false
	default:
		return true
	}
}

// finalize sorts hosts and subnets for more performant further usage.  It does
// nothing if c is nil.
//
// TODO(e.burkov):  Since this function is not exported, it's possible to
// require for c to be non-nil.
func (c *clients) finalize() {
	if c != nil {
		slices.Sort(c.hosts)
		slices.SortFunc(c.nets, comparePrefix)
	}
}

// add adds a new client to the set.  c must be not be nil, and must be sorted
// with [finalize] after all additions.
func (c *clients) add(client string) {
	if filterutil.IsProbablyIP(client) {
		ip, err := netip.ParseAddr(client)
		if err == nil {
			c.nets = append(c.nets, netip.PrefixFrom(ip, ip.BitLen()))

			return
		}
	} else if strings.Contains(client, "/") {
		subnet, err := netip.ParsePrefix(client)
		if err == nil {
			c.nets = append(c.nets, subnet.Masked())

			return
		}
	}

	c.hosts = append(c.hosts, client)
}

// newClients creates a new clients set from a list of clients.
func newClients(clientStrs ...string) (c *clients) {
	c = &clients{}
	for _, s := range clientStrs {
		c.add(s)
	}
	c.finalize()

	return c
}

// containsAny returns true if clients contain either host or the IP address
// ipStr is within one of the clients' subnets.
func (c *clients) containsAny(host string, ip netip.Addr) (ok bool) {
	if c == nil {
		return false
	}

	if host != "" {
		if _, ok = slices.BinarySearch(c.hosts, host); ok {
			return true
		}
	}

	if ip == (netip.Addr{}) {
		return false
	}

	for _, n := range c.nets {
		if n.Contains(ip) {
			return true
		}
	}

	return false
}

// comparePrefix is a comparison function for sorting slices of [netip.Prefix].
// It prefers IPv4 over IPv6, and shorter prefixes over longer ones.
func comparePrefix(a, b netip.Prefix) (res int) {
	addrA, addrB := a.Addr(), b.Addr()

	aIs4, bIs4 := addrA.Is4(), addrB.Is4()
	if aIs4 != bIs4 {
		if aIs4 {
			return -1
		}

		return 1
	}

	bitsA, bitsB := a.Bits(), b.Bits()
	if bitsA < bitsB {
		return -1
	} else if bitsA > bitsB {
		return 1
	}

	return addrA.Compare(addrB)
}
