package rules

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// RCode is a semantic alias for int when used as a DNS response code RCODE.
type RCode = int

// RRType is a semantic alias for uint16 when used as a DNS resource record (RR)
// type.
type RRType = uint16

// RRValue is the value of a resource record.
//
// If the coresponding RRType is either dns.TypeA or dns.TypeAAAA, the
// underlying type of RRValue is net.IP.
//
// If the RRType is dns.TypeMX, the underlying value is a non-nil *DNSMX.
//
// If the RRType is either dns.TypePTR or dns.TypeTXT, the underlying type of
// Value is string.
//
// If the RRType is either dns.TypeHTTPS or dns.TypeSVCB, the underlying value
// is a non-nil *DNSSVCB.
//
// Otherwise, currently, it is nil.  New types may be added in the future.
type RRValue = interface{}

// DNSRewrite is a DNS rewrite ($dnsrewrite) rule.
type DNSRewrite struct {
	// Value is the value for the record.  See the RRValue documentation for
	// more details.
	Value RRValue
	// NewCNAME is the new CNAME.  If set, clients must ignore other fields,
	// resolve the CNAME, and set the new A and AAAA records accordingly.
	NewCNAME string
	// RCode is the new DNS RCODE.
	RCode RCode
	// RRType is the new DNS resource record (RR) type.  It is only non-zero
	// if RCode is dns.RCodeSuccess.
	RRType RRType
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

// isValidHostRune returns true if r is a valid rune for a hostname part.
func isValidHostRune(r rune) (ok bool) {
	return r == '-' || isValidHostFirstRune(r)
}

// isValidHostFirstRune returns true if r is a valid first rune for a hostname
// part.
func isValidHostFirstRune(r rune) (ok bool) {
	return (r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9')
}

// validateHost validates the host in accordance to RFC-952 with RFC-1123's
// inclusion of digits at the start of the host.  It also doesn't validate
// against two or more hyphens to allow punycode and internationalized domains.
//
// TODO(a.garipov):  !!  a test suite.
func validateHost(host string) (err error) {
	l := len(host)
	if l == 0 || l > 63 {
		return fmt.Errorf("invalid hostname length: %d", l)
	}

	parts := strings.Split(host, ".")
	for i, p := range parts {
		if len(p) == 0 {
			return fmt.Errorf("empty hostname part at index %d", i)
		}

		if r := p[0]; !isValidHostFirstRune(rune(r)) {
			return fmt.Errorf("invalid hostname part at index %d: invalid char %q at index %d", i, r, 0)
		}

		for j, r := range p[1:] {
			if !isValidHostRune(r) {
				return fmt.Errorf("invalid hostname part at index %d: invalid char %q at index %d", i, r, j+1)
			}
		}
	}

	return nil
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

	err = validateHost(s)
	if err != nil {
		return nil, fmt.Errorf("invalid shorthand hostname %q: %w", s, err)
	}

	return &DNSRewrite{
		NewCNAME: s,
	}, nil
}

// DNSMX is the type of RRValue values returned for MX records in DNS rewrites.
type DNSMX struct {
	Exchange   string
	Preference uint16
}

// DNSSVCB is the type of RRValue values returned for HTTPS and SVCB records in
// dns rewrites.
//
// See https://tools.ietf.org/html/draft-ietf-dnsop-svcb-https-01.
type DNSSVCB struct {
	Params   map[string]string
	Target   string
	Priority uint16
}

// dnsRewriteRRHandler is a function that parses values for specific resource
// record types.
type dnsRewriteRRHandler func(rcode RCode, rr RRType, valStr string) (dnsr *DNSRewrite, err error)

// strDNSRewriteRRHandler is a simple DNS rewrite handler that returns
// a *DNSRewrite with Value st to valStr.
func strDNSRewriteRRHandler(rcode RCode, rr RRType, valStr string) (dnsr *DNSRewrite, err error) {
	return &DNSRewrite{
		RCode:  rcode,
		RRType: rr,
		Value:  valStr,
	}, nil
}

// svcbDNSRewriteRRHandler is a DNS rewrite handler that parses SVCB and HTTPS
// rewrites.
//
// See https://tools.ietf.org/html/draft-ietf-dnsop-svcb-https-01.
//
// TODO(a.garipov): Currently, we only support the contiguous type of
// char-string values from the RFC.
func svcbDNSRewriteRRHandler(rcode RCode, rr RRType, valStr string) (dnsr *DNSRewrite, err error) {
	var name string
	switch rr {
	case dns.TypeHTTPS:
		name = "https"
	case dns.TypeSVCB:
		name = "svcb"
	default:
		return nil, fmt.Errorf("unsupported svcb-like rr type: %d", rr)
	}

	fields := strings.Split(valStr, " ")
	if len(fields) < 2 {
		return nil, fmt.Errorf("invalid %s %q: need at least two fields", name, valStr)
	}

	var prio64 uint64
	prio64, err = strconv.ParseUint(fields[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid %s priority: %w", name, err)
	}

	if len(fields) == 2 {
		v := &DNSSVCB{
			Priority: uint16(prio64),
			Target:   fields[1],
		}

		return &DNSRewrite{
			RCode:  rcode,
			RRType: rr,
			Value:  v,
		}, nil
	}

	params := make(map[string]string, len(fields)-2)
	for i, pair := range fields[2:] {
		kv := strings.Split(pair, "=")
		if l := len(kv); l != 2 {
			return nil, fmt.Errorf("invalid %s param at index %d: got %d fields", name, i, l)
		}

		// TODO(a.garipov): Validate for uniqueness?  Validate against
		// the currently specified list of params from the RFC?
		params[kv[0]] = kv[1]
	}

	v := &DNSSVCB{
		Priority: uint16(prio64),
		Target:   fields[1],
		Params:   params,
	}

	return &DNSRewrite{
		RCode:  rcode,
		RRType: rr,
		Value:  v,
	}, nil
}

// dnsRewriteRRHandlers are the supported resource record types' rewrite
// handlers.
var dnsRewriteRRHandlers = map[RRType]dnsRewriteRRHandler{
	dns.TypeA: func(rcode RCode, rr RRType, valStr string) (dnsr *DNSRewrite, err error) {
		ip := net.ParseIP(valStr)
		if ip4 := ip.To4(); ip4 == nil {
			return nil, fmt.Errorf("invalid ipv4: %q", valStr)
		}

		return &DNSRewrite{
			RCode:  rcode,
			RRType: rr,
			Value:  ip,
		}, nil
	},

	dns.TypeAAAA: func(rcode RCode, rr RRType, valStr string) (dnsr *DNSRewrite, err error) {
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
	},

	dns.TypeCNAME: func(rcode RCode, rr RRType, valStr string) (dnsr *DNSRewrite, err error) {
		return &DNSRewrite{
			NewCNAME: valStr,
		}, nil
	},

	dns.TypeMX: func(rcode RCode, rr RRType, valStr string) (dnsr *DNSRewrite, err error) {
		parts := strings.SplitN(valStr, " ", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid mx: %q", valStr)
		}

		var pref64 uint64
		pref64, err = strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid mx preference: %w", err)
		}

		v := &DNSMX{
			Exchange:   parts[1],
			Preference: uint16(pref64),
		}

		return &DNSRewrite{
			RCode:  rcode,
			RRType: rr,
			Value:  v,
		}, nil
	},

	dns.TypePTR: strDNSRewriteRRHandler,
	dns.TypeTXT: strDNSRewriteRRHandler,

	dns.TypeHTTPS: svcbDNSRewriteRRHandler,
	dns.TypeSVCB:  svcbDNSRewriteRRHandler,
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

	rr, err := strToRRType(rrStr)
	if err != nil {
		return nil, err
	}

	handler, ok := dnsRewriteRRHandlers[rr]
	if !ok {
		return &DNSRewrite{
			RCode:  rcode,
			RRType: rr,
		}, nil
	}

	return handler(rcode, rr, valStr)
}
