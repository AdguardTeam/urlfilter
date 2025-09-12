package urlfilter

import (
	"slices"

	"github.com/AdguardTeam/urlfilter/rules"
)

// DNSResult is the result of matching a DNS filtering request.
type DNSResult struct {
	// NetworkRule is the matched network rule, if any.  If it is nil,
	// HostRulesV4 and HostRulesV6 may still contain matched hosts-file style
	// rules.
	NetworkRule *rules.NetworkRule

	// HostRulesV4 are the host rules with IPv4 addresses.
	HostRulesV4 []*rules.HostRule

	// HostRulesV6 are the host rules with IPv6 addresses.
	HostRulesV6 []*rules.HostRule

	// NetworkRules are all matched network rules.  These include unprocessed
	// DNS rewrites, exception rules, and so on.
	NetworkRules []*rules.NetworkRule
}

// ShallowCloneInto sets properties in other, as if making a shallow clone.
// other must not be nil and should be empty or reset using [DNSResult.Reset].
func (res *DNSResult) ShallowCloneInto(other *DNSResult) {
	// TODO(a.garipov):  Add ways of making deep clones of rules.
	other.NetworkRule = res.NetworkRule
	other.HostRulesV4 = append(other.HostRulesV4, res.HostRulesV4...)
	other.HostRulesV6 = append(other.HostRulesV6, res.HostRulesV6...)
	other.NetworkRules = append(other.NetworkRules, res.NetworkRules...)
}

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
// [DNSResult.DNSRewritesAll].
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

// Reset makes res ready for reuse.
func (res *DNSResult) Reset() {
	res.NetworkRule = nil
	res.HostRulesV4 = res.HostRulesV4[:0]
	res.HostRulesV6 = res.HostRulesV6[:0]
	res.NetworkRules = res.NetworkRules[:0]
}
