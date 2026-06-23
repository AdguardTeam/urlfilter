package urlfilter

import (
	"net/netip"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/urlfilter/internal/geoip"
	"github.com/AdguardTeam/urlfilter/rules"
)

// DNSRequest represents a DNS query with associated metadata.
type DNSRequest struct {
	// ClientTags is the list of tags to match against $ctag modifiers.
	ClientTags *container.SortedSliceSet[string]

	// ClientIdentifiers is the list of client IDs to match against $client
	// modifiers.
	ClientIdentifiers *container.SortedSliceSet[string]

	// ClientIP is the IP address to match against $client modifiers.  The
	// default zero value won't be considered.
	ClientIP netip.Addr

	// ResponseCountry is the country ISO code of the DNS response to match
	// the request target against rules with $respgeo modifiers.
	ResponseCountry string

	// Hostname is the hostname to filter.
	Hostname string

	// ResponseASN is the AS number of the DNS response to match the request
	// target against rules with $respgeo modifiers.
	ResponseASN uint32

	// DNSType is the type of the resource record (RR) of a DNS request, for
	// example "A" or "AAAA".  See [rules.RRValue] for all acceptable constants
	// and their corresponding values.
	DNSType rules.RRType

	// Answer if the filtering request is for filtering a DNS response.
	Answer bool
}

// Reset makes r ready for reuse.
func (r *DNSRequest) Reset() {
	r.ClientIP = netip.Addr{}

	r.ClientIdentifiers.Clear()
	r.Hostname = ""

	r.ResponseCountry = geoip.CountryNone
	r.ResponseASN = geoip.ASNNone

	r.ClientTags.Clear()

	r.DNSType = 0

	r.Answer = false
}
