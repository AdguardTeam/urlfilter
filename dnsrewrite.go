package urlfilter

import (
	"slices"

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

// removeMatchingException changes nrules in-place to remove the elements that
// match DNS rewrite exception rule exc and returns the resulting slice.  exc
// must not be nil.
func removeMatchingException(
	nrules []*rules.NetworkRule,
	exc *rules.NetworkRule,
) (flt []*rules.NetworkRule) {
	if exc.DNSRewrite == nil {
		return nrules
	}

	excImportant := exc.IsOptionEnabled(rules.OptionImportant)
	if *exc.DNSRewrite == (rules.DNSRewrite{}) {
		if excImportant {
			// Rule with "$important,dnsrewrite" disables all DNS rewrite rules.
			return nil
		}

		// Rule with "$dnsrewrite" disables any other except important.
		return slices.DeleteFunc(nrules, func(nr *rules.NetworkRule) bool {
			return !nr.IsOptionEnabled(rules.OptionImportant)
		})
	}

	nrules = slices.DeleteFunc(nrules, func(nr *rules.NetworkRule) bool {
		return matchException(nr, exc, excImportant)
	})

	return nrules
}

// matchException returns true if the exception disables the rule.
func matchException(nr, exc *rules.NetworkRule, excImportant bool) (ok bool) {
	if !excImportant && nr.IsOptionEnabled(rules.OptionImportant) {
		// Do not match important rules unless the exc is important.
		return false
	}

	nrdnsr := nr.DNSRewrite
	excdnsr := exc.DNSRewrite

	if excdnsr.NewCNAME != "" {
		return nrdnsr.NewCNAME == excdnsr.NewCNAME
	}

	if nrdnsr.RCode == excdnsr.RCode {
		if excdnsr.RCode != dns.RcodeSuccess {
			return true
		}

		if nrdnsr.RRType == excdnsr.RRType && nrdnsr.Value == excdnsr.Value {
			return true
		}
	}

	return false
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
			nrules = slices.Delete(nrules, i, i+1)
			nrules = removeMatchingException(nrules, nr)
		}
	}

	return nrules
}
