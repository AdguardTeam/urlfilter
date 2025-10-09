package rules

import (
	"net/netip"
	"slices"

	"github.com/AdguardTeam/golibs/netutil"
)

// clients is a set representation for $client modifier.
type clients struct {
	// identifiers are the client string identifiers, that are neither IP
	// addresses nor subnets.
	//
	// TODO(e.burkov):  Think of using [container.MapSet].
	identifiers []string

	// nets are the clients defined by IP addresses or subnets.
	nets netutil.SliceSubnetSet
}

// len returns the number of specified identifiers.  If c is nil, l is 0.
func (c *clients) len() (l int) {
	if c == nil {
		return 0
	}

	return len(c.identifiers) + len(c.nets)
}

// equal returns true if c and other contain the same identifiers in the same
// order.  c and other may be nil.
func (c *clients) equal(other *clients) (ok bool) {
	switch {
	case c == nil:
		return other == nil
	case
		other == nil,
		!slices.Equal(c.identifiers, other.identifiers),
		!slices.Equal(c.nets, other.nets):
		return false
	default:
		return true
	}
}

// add adds a new client to the set.
func (c *clients) add(client string) {
	var pref netip.Prefix
	switch {
	case netutil.IsValidIPString(client):
		ip := netip.MustParseAddr(client)
		pref = netip.PrefixFrom(ip, ip.BitLen()).Masked()
	case netutil.IsValidIPPrefixString(client):
		pref = netip.MustParsePrefix(client).Masked()
	default:
		idx, ok := slices.BinarySearch(c.identifiers, client)
		if !ok {
			c.identifiers = slices.Insert(c.identifiers, idx, client)
		}

		return
	}

	idx, ok := slices.BinarySearchFunc(c.nets, pref, comparePrefix)
	if !ok {
		c.nets = slices.Insert(c.nets, idx, pref)
	}
}

// newClients creates a new clients set from a slice of clients.
func newClients(clientStrs ...string) (c *clients) {
	c = &clients{}
	for _, s := range clientStrs {
		c.add(s)
	}

	return c
}

// containsAny returns true if clients contain either host or the IP address
// ipStr is within one of the clients' subnets.  If c is nil, ok is false.
func (c *clients) containsAny(host string, ip netip.Addr) (ok bool) {
	if c == nil {
		return false
	}

	if host != "" {
		if _, ok = slices.BinarySearch(c.identifiers, host); ok {
			return true
		}
	}

	return ip != (netip.Addr{}) && c.nets.Contains(ip)
}

// comparePrefix is a comparison function for sorting slices of [netip.Prefix].
// It prefers IPv4 over IPv6, and shorter prefixes over longer ones.
//
// TODO(a.garipov):  Consider removing in Go 1.26.
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
