package rules

import (
	"bytes"
	"net"
	"sort"

	"github.com/AdguardTeam/urlfilter/filterutil"
)

// set representation for $client modifiers
type clients struct {
	hosts []string
	nets  ipNets
}

func (c *clients) Len() int {
	if c == nil {
		return 0
	}
	return len(c.hosts) + len(c.nets)
}

func (c *clients) Equal(other *clients) bool {
	if c == nil {
		return other == nil
	}
	if other == nil {
		return false
	}

	if !stringArraysEquals(c.hosts, other.hosts) {
		return false
	}

	if len(c.nets) != len(other.nets) {
		return false
	}

	for i, subnet := range c.nets {
		if subnet.String() != other.nets[i].String() {
			return false
		}
	}

	return true
}

func (c *clients) finalize() {
	if c != nil {
		sort.Strings(c.hosts)
		sort.Sort(c.nets)
	}
}

// c != nil
func (c *clients) add(client string) {
	_, subnet, err := net.ParseCIDR(client)
	if err == nil {
		c.nets = append(c.nets, *subnet)
		return
	}

	ip := filterutil.ParseIP(client)
	if ip != nil {
		mask := net.CIDRMask(32, 32)
		if ip.To4() == nil {
			mask = net.CIDRMask(128, 128)
		}
		c.nets = append(c.nets, net.IPNet{IP: ip, Mask: mask})
		return
	}

	c.hosts = append(c.hosts, client)
}

func newClients(clientStrs ...string) *clients {
	c := &clients{}
	for _, clientStr := range clientStrs {
		c.add(clientStr)
	}
	c.finalize()
	return c
}

// containsAny returns true if clients contain either host or the IP
// address ipStr is within one of the clients' subnets.
func (c *clients) containsAny(host, ipStr string) bool {
	if c == nil {
		return false
	}

	if findSorted(c.hosts, host) != -1 {
		return true
	}

	ip := filterutil.ParseIP(ipStr)
	if ip != nil {
		for _, subnet := range c.nets {
			if subnet.Contains(ip) {
				return true
			}
		}
	}

	return false
}

type ipNets []net.IPNet

var _ sort.Interface = (*ipNets)(nil)

func (n ipNets) Len() int {
	return len(n)
}

func (n ipNets) Less(i, j int) bool {
	// ipv4 < ipv6
	if n[i].IP.To4() == nil {
		if n[j].IP.To4() != nil {
			return false
		}
	} else {
		if n[j].IP.To4() == nil {
			return true
		}
	}

	// bigger subnets < smaller subnets
	iMaskSize, _ := n[i].Mask.Size()
	jMaskSize, _ := n[j].Mask.Size()
	if iMaskSize < jMaskSize {
		return true
	} else if iMaskSize > jMaskSize {
		return false
	}

	// normalized network number byte order
	if bytes.Compare(n[i].IP.To16(), n[j].IP.To16()) == -1 {
		return true
	}

	return false
}

func (n ipNets) Swap(i, j int) {
	t := n[i]
	n[i] = n[j]
	n[j] = t
}
