package lookup

import (
	"strings"

	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/filterutil"
	"github.com/AdguardTeam/urlfilter/rules"
)

// DomainsTable is a lookup table that uses domains from the $domain modifier
// to speed up the rules search.  Only the rules with $domain modifier are
// eligible for this lookup table.
type DomainsTable struct {
	// Storage for the network filtering rules.
	ruleStorage *filterlist.RuleStorage

	// Domain lookup table. Key is the domain name hash.
	domainsLookupTable map[uint32][]int64
}

// type check
var _ Table = (*DomainsTable)(nil)

// NewDomainsTable creates a new instance of the DomainsTable.
func NewDomainsTable(rs *filterlist.RuleStorage) (s *DomainsTable) {
	return &DomainsTable{
		ruleStorage:        rs,
		domainsLookupTable: map[uint32][]int64{},
	}
}

// TryAdd implements the LookupTable interface for *DomainsTable.
func (d *DomainsTable) TryAdd(f *rules.NetworkRule, storageIdx int64) (ok bool) {
	permittedDomains := f.GetPermittedDomains()
	if len(permittedDomains) == 0 {
		return false
	}

	for _, domain := range permittedDomains {
		hash := filterutil.FastHash(domain)

		// Add the rule to the lookup table
		rulesIndexes := d.domainsLookupTable[hash]
		rulesIndexes = append(rulesIndexes, storageIdx)
		d.domainsLookupTable[hash] = rulesIndexes
	}

	return true
}

// MatchAll implements the LookupTable interface for *DomainsTable.
func (d *DomainsTable) MatchAll(r *rules.Request) (result []*rules.NetworkRule) {
	if r.SourceHostname == "" {
		return result
	}

	domains := getSubdomains(r.SourceHostname)
	for _, domain := range domains {
		hash := filterutil.FastHash(domain)
		matchingRules, ok := d.domainsLookupTable[hash]
		if !ok {
			continue
		}

		for _, ruleIdx := range matchingRules {
			rule := d.ruleStorage.RetrieveNetworkRule(ruleIdx)
			if rule != nil && rule.Match(r) {
				result = append(result, rule)
			}
		}
	}
	return result
}

// getSubdomains splits the specified hostname and returns all subdomains
// (including the hostname itself).
// TODO(ameshkov): consider doing this in rules.Request
func getSubdomains(hostname string) (subdomains []string) {
	parts := strings.Split(hostname, ".")
	domain := ""
	for i := len(parts) - 1; i >= 0; i-- {
		if domain == "" {
			domain = parts[i]
		} else {
			domain = parts[i] + "." + domain
		}
		subdomains = append(subdomains, domain)
	}
	return subdomains
}
