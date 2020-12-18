package rules

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// RCode is a semantic alias for int when used as a DNS response code RCODE.
type RCode = int

// RRType is a semantic alias for uint16 when used as a DNS resource record (RR)
// type.
type RRType = uint16

// RRValue is the value of a resource record.  If the coresponding RR is either
// dns.TypeA or dns.TypeAAAA, the underlying type of RRValue is net.IP.  If the
// RR is dns.TypeTXT, the underlying type of Value is string.  Otherwise,
// currently, it is nil.  New types may be added in the future.
type RRValue = interface{}

// DNSRewrite is a DNS rewrite ($dnsrewrite) rule.
type DNSRewrite struct {
	// RCode is the new DNS RCODE.
	RCode RCode
	// RRType is the new DNS resource record (RR) type.  It is only non-zero
	// if RCode is dns.RCodeSuccess.
	RRType RRType
	// Value is the value for the record.  See the RRValue documentation for
	// more details.
	Value RRValue
	// NewCNAME is the new CNAME.  If set, clients must ignore other fields,
	// resolve the CNAME, and set the new A and AAAA records accordingly.
	NewCNAME string
}

// loadDNSRewrite loads the $dnsrewrite modifier.
func loadDNSRewrite(s string) (rewrite *DNSRewrite, err error) {
	parts := strings.SplitN(s, ";", 3)
	switch len(parts) {
	case 1:
		return loadDNSRewriteShort(s)
	case 2:
		return nil, errors.New("invalid dnsrewrite: expected zero or two delimiters")
	case 3:
		return loadDNSRewriteNormal(parts[0], parts[1], parts[2])
	default:
		// TODO(a.garipov): Use panic("unreachable") instead?
		return nil, fmt.Errorf("SplitN returned %d parts", len(parts))
	}
}

// allUppercaseASCII returns true if s is not empty and all characters in s are
// uppercase ASCII letters.
func allUppercaseASCII(s string) (ok bool) {
	if s == "" {
		return false
	}

	for _, r := range s {
		if r < 'A' || r > 'Z' {
			return false
		}
	}

	return true
}

// loadDNSRewritesShort loads the shorthand version of the $dnsrewrite modifier.
func loadDNSRewriteShort(s string) (rewrite *DNSRewrite, err error) {
	if s == "" {
		// Return an empty DNSRewrite, because an empty string most
		// probalby means that this is a disabling allowlist case.
		return &DNSRewrite{}, nil
	} else if allUppercaseASCII(s) {
		if s == "REFUSED" {
			return &DNSRewrite{
				RCode: dns.RcodeRefused,
			}, nil
		}

		return nil, fmt.Errorf("unknown keyword: %q", s)
	}

	ip := net.ParseIP(s)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return &DNSRewrite{
				RCode:  dns.RcodeSuccess,
				RRType: dns.TypeA,
				Value:  ip,
			}, nil
		}

		return &DNSRewrite{
			RCode:  dns.RcodeSuccess,
			RRType: dns.TypeAAAA,
			Value:  ip,
		}, nil
	}

	return &DNSRewrite{
		NewCNAME: s,
	}, nil
}

// loadDNSRewritesNormal loads the normal version for of the $dnsrewrite
// modifier.
func loadDNSRewriteNormal(rcodeStr, rrStr, valStr string) (rewrite *DNSRewrite, err error) {
	rcode, ok := dns.StringToRcode[strings.ToUpper(rcodeStr)]
	if !ok {
		return nil, fmt.Errorf("unknown rcode: %q", rcodeStr)
	}

	if rcode != dns.RcodeSuccess {
		return &DNSRewrite{
			RCode: rcode,
		}, nil
	}

	rr, err := strToRR(rrStr)
	if err != nil {
		return nil, err
	}

	switch rr {
	case dns.TypeA:
		ip := net.ParseIP(valStr)
		if ip4 := ip.To4(); ip4 == nil {
			return nil, fmt.Errorf("invalid ipv4: %q", valStr)
		}

		return &DNSRewrite{
			RCode:  rcode,
			RRType: rr,
			Value:  ip,
		}, nil
	case dns.TypeAAAA:
		ip := net.ParseIP(valStr)
		if ip == nil {
			return nil, fmt.Errorf("invalid ipv6: %q", valStr)
		} else if ip4 := ip.To4(); ip4 != nil {
			return nil, fmt.Errorf("want ipv6, got ipv4: %q", valStr)
		}

		return &DNSRewrite{
			RCode:  rcode,
			RRType: rr,
			Value:  ip,
		}, nil
	case dns.TypeCNAME:
		return &DNSRewrite{
			NewCNAME: valStr,
		}, nil
	case dns.TypeTXT:
		return &DNSRewrite{
			RCode:  rcode,
			RRType: rr,
			Value:  valStr,
		}, nil
	default:
		return &DNSRewrite{
			RCode:  rcode,
			RRType: rr,
		}, nil
	}
}
