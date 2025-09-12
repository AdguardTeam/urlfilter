package urlfilter

import (
	"slices"

	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
)

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
