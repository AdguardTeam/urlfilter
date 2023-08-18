package rules

import (
	"bytes"
	"net"

	"github.com/AdguardTeam/urlfilter/filterutil"
	"golang.org/x/exp/slices"
)

// set representation for $client modifiers
type clients struct {
	hosts []string
	nets  []*net.IPNet
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
		slices.Sort(c.hosts)
		slices.SortFunc(c.nets, compareIPNets)
	}
}

// c != nil
func (c *clients) add(client string) {
	_, subnet, err := net.ParseCIDR(client)
	if err == nil {
		c.nets = append(c.nets, subnet)

		return
	}

	ip := filterutil.ParseIP(client)
	if ip != nil {
		var mask net.IPMask
		if ip.To4() == nil {
			mask = net.CIDRMask(128, 128)
		} else {
			mask = net.CIDRMask(32, 32)
		}
		c.nets = append(c.nets, &net.IPNet{IP: ip, Mask: mask})

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

func compareIPNets(i, j *net.IPNet) int {
	// ipv4 < ipv6
	if i.IP.To4() == nil {
		if j.IP.To4() != nil {
			return 1
		}
	} else {
		if j.IP.To4() == nil {
			return -1
		}
	}

	// bigger subnets < smaller subnets
	iMaskSize, _ := i.Mask.Size()
	jMaskSize, _ := j.Mask.Size()
	if iMaskSize < jMaskSize {
		return -1
	} else if iMaskSize > jMaskSize {
		return 1
	}

	// normalized network number byte order
	return bytes.Compare(i.IP.To16(), j.IP.To16())
}
