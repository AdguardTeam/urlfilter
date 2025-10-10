package lookup

import (
	"strings"

	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
)

// DomainIndex is an index that uses domains from the $domain modifier to speed
// up the rules search.  Only the rules with $domain modifier are eligible for
// this index.
type DomainIndex struct {
	// subdomainsPool contains slices of strings to fill with subdomains.
	subdomainsPool *syncutil.Pool[[]string]

	// domainsIndex is the index of domains to IDs of the rules that match them.
	domainsIndex map[string][]filterlist.StorageID
}

// subdomainsEst is the estimate for the number of subdomains in a domain.
const subdomainsEst = 4

// NewDomainIndex creates a new instance of the DomainIndex.
func NewDomainIndex() (idx *DomainIndex) {
	return &DomainIndex{
		subdomainsPool: syncutil.NewSlicePool[string](subdomainsEst),
		domainsIndex:   map[string][]filterlist.StorageID{},
	}
}

// Add adds r to the index if r is eligible.  r must not be nil.
func (idx *DomainIndex) Add(r *rules.NetworkRule, id filterlist.StorageID) (ok bool) {
	permittedDomains := r.GetPermittedDomains()
	if len(permittedDomains) == 0 {
		return false
	}

	for _, domain := range permittedDomains {
		rulesIndexes := idx.domainsIndex[domain]
		rulesIndexes = append(rulesIndexes, id)
		idx.domainsIndex[domain] = rulesIndexes
	}

	return true
}

// AppendMatching appends the IDs of the rules matching r to orig and returns
// it.  r must not be nil.
func (idx *DomainIndex) AppendMatching(
	orig []filterlist.StorageID,
	r *rules.Request,
) (res []filterlist.StorageID) {
	res = orig

	if r.SourceHostname == "" {
		return res
	}

	subdomainsPtr := idx.subdomainsPool.Get()
	defer idx.subdomainsPool.Put(subdomainsPtr)

	*subdomainsPtr = appendSubdomains((*subdomainsPtr)[:0], r.SourceHostname)
	if len(*subdomainsPtr) == 0 {
		return res
	}

	for _, domain := range *subdomainsPtr {
		res = append(res, idx.domainsIndex[domain]...)
	}

	return res
}

// appendSubdomains appends all subdomains of domain, starting from domain
// itself, to sub.  domain must be a valid, non-fully-qualified domain name.
// If domain is empty, appendSubdomains returns nil.
//
// NOTE:  Keep in sync with [netutil.Subdomains].
//
// TODO(a.garipov):  Add to golibs.
func appendSubdomains(sub []string, domain string) (res []string) {
	if domain == "" {
		return nil
	}

	res = append(sub, domain)

	for domain != "" {
		i := strings.IndexByte(domain, '.')
		if i < 0 {
			break
		}

		domain = domain[i+1:]
		res = append(res, domain)
	}

	return res
}

// Reset prepares idx for reuse.
func (idx *DomainIndex) Reset() {
	clear(idx.domainsIndex)
}
