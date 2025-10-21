package lookup

import (
	"encoding"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/internal/ufcbor"
	"github.com/AdguardTeam/urlfilter/internal/ufencoding"
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

// type check
var _ encoding.BinaryAppender = (*DomainIndex)(nil)

// AppendBinary implements the [encoding.BinaryAppender] interface for
// *DomainIndex.  The only guarantee with regards to the backwards compatibility
// is the following: when the result of AppendBinary is fed into
// [DomainIndex.UnmarshalBinary] of an empty or reset *DomainIndex, the results
// of [DomainIndex.AppendMatching] of this new table are the same as those of
// the original one; all of this being within one version of the module.
func (idx *DomainIndex) AppendBinary(orig []byte) (res []byte, err error) {
	// Pseudo-JSON of the CBOR output:
	//	{
	//	  "domain1.example": [
	//	    [ 1, 0 ],
	//	    [ 1, 1 ],
	//	    // …
	//	  ],
	//	  "domain2.example": [
	//	    [ 1, 1 ],
	//	    [ 1, 2 ],
	//	    // …
	//	  ],
	//	  // …
	//	}

	res = orig

	enc := ufcbor.NewEncoder()

	res = enc.EncodeMapStart(res, uint64(len(idx.domainsIndex)))
	for _, domain := range slices.Sorted(maps.Keys(idx.domainsIndex)) {
		res = enc.EncodeBytes(res, []byte(domain))

		ids := idx.domainsIndex[domain]
		res = enc.EncodeArrayStart(res, uint64(len(ids)))
		for i, id := range ids {
			res, err = id.AppendBinary(res)
			if err != nil {
				return res, fmt.Errorf("domain %q: encoding id at index %d: %w", domain, i, err)
			}
		}
	}

	return res, nil
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

// type check
var _ encoding.BinaryUnmarshaler = (*DomainIndex)(nil)

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface for
// *DomainIndex.  b should be data that has been encoded by
// [DomainIndex.AppendBinary].
func (idx *DomainIndex) UnmarshalBinary(b []byte) (err error) {
	_, err = idx.UnmarshalBinaryRest(b)

	return err
}

// type check
var _ ufencoding.BinaryUnmarshalerRest = (*DomainIndex)(nil)

// UnmarshalBinaryRest implements the [ufencoding.BinaryUnmarshalerRest]
// interface for *DomainIndex.  b should be data that has been encoded by
// [DomainIndex.AppendBinary].
func (idx *DomainIndex) UnmarshalBinaryRest(b []byte) (rest []byte, err error) {
	rest = b
	dec := ufcbor.NewDecoder()

	l, rest := dec.DecodeMapStart(rest)

	var keyBuffer []byte
	idx.domainsIndex = make(map[string][]filterlist.StorageID, l)
	for range l {
		keyBuffer, rest = dec.AppendBytes(keyBuffer[:0], rest)

		var idsLen uint64
		idsLen, rest = dec.DecodeArrayStart(rest)

		ids := make([]filterlist.StorageID, 0, idsLen)
		for i := range idsLen {
			var id filterlist.StorageID
			rest, err = id.UnmarshalBinaryRest(rest)
			if err != nil {
				return b, fmt.Errorf("decoding domain %q: id at index %d: %w", keyBuffer, i, err)
			}

			ids = append(ids, id)
		}

		idx.domainsIndex[string(keyBuffer)] = ids
	}

	err = dec.Err()
	if err != nil {
		return b, err
	}

	return rest, nil
}
