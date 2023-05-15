package urlfilter

import (
	"sort"

	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
)

// DNSRewritesAll returns all $dnsrewrite network rules.  To get the rules with
// exception logic applied, use (*DNSResult).DNSRewrites.
func (res *DNSResult) DNSRewritesAll() (nrules []*rules.NetworkRule) {
	if res == nil {
		return nil
	}

	for _, nr := range res.NetworkRules {
		if nr.DNSRewrite != nil {
			nrules = append(nrules, nr)
		}
	}

	return nrules
}

// removeNetworkRule changes nrules in-place to remove the element at index
// i and returns the resulting slice.
func removeNetworkRule(nrules []*rules.NetworkRule, i int) (flt []*rules.NetworkRule) {
	// See https://github.com/golang/go/wiki/SliceTricks#delete.
	//
	// TODO(a.garipov): Use golang.org/x/exp/slices in Go 1.18.
	return append(nrules[:i], nrules[i+1:]...)
}

// removeMatchingException changes nrules in-place to remove the elements that
// match DNS rewrite exception rule exc and returns the resulting slice.
func removeMatchingException(nrules []*rules.NetworkRule, exc *rules.NetworkRule) (flt []*rules.NetworkRule) {
	if exc.DNSRewrite == nil {
		return nrules
	}

	excdnsr := exc.DNSRewrite
	if *excdnsr == (rules.DNSRewrite{}) {
		// A rule like:
		//
		//   $dnsrewrite=
		//
		// Which means disabling all DNS rewrite rules.
		return nil
	}

	// Use the three-statement form as opposed to the range form, because we
	// change the slice in-place.
	for i := 0; i < len(nrules); i++ {
		nr := nrules[i]
		nrdnsr := nr.DNSRewrite
		if nrdnsr.NewCNAME == excdnsr.NewCNAME {
			nrules = removeNetworkRule(nrules, i)

			continue
		}

		if nrdnsr.RCode == excdnsr.RCode {
			if excdnsr.RCode != dns.RcodeSuccess {
				nrules = removeNetworkRule(nrules, i)

				continue
			}

			if nrdnsr.RRType == excdnsr.RRType && nrdnsr.Value == excdnsr.Value {
				nrules = removeNetworkRule(nrules, i)
			}
		}
	}

	return nrules
}

// DNSRewrites returns $dnsrewrite network rules applying exception logic.  For
// example, rules like:
//
//	||example.com^$dnsrewrite=127.0.0.1
//	||example.com^$dnsrewrite=127.0.0.2
//	@@||example.com^$dnsrewrite=127.0.0.1
//
// Will result in example.com being rewritten to only return 127.0.0.2.
//
// To get all DNS rewrite rules without applying any exception logic, use
// (*DNSResult).DNSRewritesAll.
func (res *DNSResult) DNSRewrites() (nrules []*rules.NetworkRule) {
	// This is currently an O(m×n) algorithm, but the m--the number
	// of $dnsrewrite rules--will probably remain way below 10, and
	// so will n--the number of exceptions.

	if res == nil {
		return nil
	}

	nrules = res.DNSRewritesAll()

	// Use the three-statement form as opposed to the range form, because we
	// change the slice in-place.
	for i := 0; i < len(nrules); i++ {
		nr := nrules[i]
		if nr.Whitelist {
			nrules = removeNetworkRule(nrules, i)
			nrules = removeMatchingException(nrules, nr)
		}
	}

	sort.Slice(nrules, func(i, j int) bool {
		return len(nrules[i].Shortcut) > len(nrules[j].Shortcut)
	})

	for i, nr := range nrules {
		if i > 0 && containsWildcard(nr) {
			nrules = nrules[:i]

			break
		}
	}

	return nrules
}

func containsWildcard(nr *rules.NetworkRule) (ok bool) {
	for _, c := range nr.RuleText {
		if c == '*' {
			return true
		} else if c == '^' {
			break
		}
	}

	return false
}
