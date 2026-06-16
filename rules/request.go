package rules

import (
	"math/bits"
	"net/netip"
	"strings"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/urlfilter/internal/ufnet"
	"golang.org/x/net/publicsuffix"
)

// maxURLLength limits the URL length by 4 KiB.  It appears that there can be
// URLs longer than a megabyte, and it makes no sense to go through the whole
// URL.
//
// TODO(a.garipov):  Reinspect.
//
// TODO(a.garipov):  Use [datasize.B]?
const maxURLLength = 4 * 1024

// RequestType is a bitset of the types of a request to be filtered.
//
// TODO(a.garipov):  Consider switching to uint16.
type RequestType uint32

// RequestType masks.
//
// See https://adguard.com/kb/general/ad-filtering/create-own-filters/#content-type-modifiers.
//
// TODO(a.garipov):  Rename consistently.
const (
	// TypeDocument means the main frame.
	TypeDocument RequestType = 1 << iota

	// TypeSubdocument means iframe requests; see the $subdocument modifier.
	TypeSubdocument

	// TypeScript means JavaScript and other script requests; see the $script
	// modifier.
	TypeScript

	// TypeStylesheet means CSS requests; see the $stylesheet modifier.
	TypeStylesheet

	// TypeObject means Flash and similar objects; see the $object modifier.
	TypeObject

	// TypeImage means images; see the $image modifier.
	TypeImage

	// TypeXmlhttprequest means AJAX or fetch requests, see the $xmlhttprequest
	// modifier.
	TypeXmlhttprequest

	// TypeMedia means video, music, etc.; see the $media modifier.
	TypeMedia

	// TypeFont means any custom font; see the $font modifier.
	TypeFont

	// TypeWebsocket means a WebSocket connection; see the $websocket modifier.
	TypeWebsocket

	// TypePing means navigator.sendBeacon() or ping attribute on links; see the
	// $ping modifier.
	TypePing

	// TypeOther means any other request type.
	TypeOther
)

// Count returns the number of the enabled request types.
func (t RequestType) Count() (n int) {
	return bits.OnesCount32(uint32(t))
}

// Request is a web filtering request.
type Request struct {
	// ClientTags is the set of tags to match against $ctag modifiers.
	ClientTags *container.SortedSliceSet[string]

	// ClientIdentifiers is the list of client IDs to match against $client
	// modifiers, if any.
	ClientIdentifiers *container.SortedSliceSet[string]

	// ClientIP is the IP address to match against $client modifiers, if any.
	ClientIP netip.Addr

	// ClientCountry is the ISO code of clients country to match against
	// $respgeo modifiers, if any.
	ClientCountry string

	// URL is the full request URL.
	URL string

	// URLLowerCase is the full request URL in lower case.
	URLLowerCase string

	// Hostname is the hostname to filter.
	Hostname string

	// Domain is the effective top-level domain of the request with an
	// additional label.
	Domain string

	// SourceURL is the full URL of the source.
	SourceURL string

	// SourceHostname is the hostname of the source.
	SourceHostname string

	// SourceDomain is the effective top-level domain of the source with an
	// additional label.
	SourceDomain string

	// RequestType is the type of the filtering request.
	RequestType RequestType

	// ClientASN is the clients ASN to match against $respgeo modifiers, if any.
	ClientASN uint32

	// DNSType is the type of the resource record (RR) of a DNS request, for
	// example A or AAAA.  See [RRValue] for all acceptable constants and their
	// corresponding values.
	DNSType uint16

	// ThirdParty is true if the filtering request should consider $third-party
	// modifier.
	ThirdParty bool

	// IsHostnameRequest means that the request is for a given Hostname, and not
	// for a URL, and we don't really know what protocol it is.  This can be
	// true for DNS requests, for HTTP CONNECT, or for SNI matching.
	IsHostnameRequest bool
}

// NewRequest returns a properly initialized *Request.
func NewRequest(url, sourceURL string, requestType RequestType) (r *Request) {
	if len(url) > maxURLLength {
		url = url[:maxURLLength]
	}
	if len(sourceURL) > maxURLLength {
		sourceURL = sourceURL[:maxURLLength]
	}

	r = &Request{
		RequestType: requestType,

		URL:          url,
		URLLowerCase: strings.ToLower(url),
		Hostname:     ufnet.ExtractHostname(url),

		SourceURL:      sourceURL,
		SourceHostname: ufnet.ExtractHostname(sourceURL),
	}

	domain := effectiveTLDPlusOne(r.Hostname)
	if domain != "" {
		r.Domain = domain
	} else {
		r.Domain = r.Hostname
	}

	sourceDomain := effectiveTLDPlusOne(r.SourceHostname)
	if sourceDomain != "" {
		r.SourceDomain = sourceDomain
	} else {
		r.SourceDomain = r.SourceHostname
	}

	if r.SourceDomain != "" && r.SourceDomain != r.Domain {
		r.ThirdParty = true
	}

	return r
}

// NewRequestForHostname creates a new instance of Request for matching the
// hostname.  It uses "http://" as a protocol and [TypeDocument] as a request
// type.
func NewRequestForHostname(hostname string) (r *Request) {
	r = &Request{}
	FillRequestForHostname(r, hostname)

	return r
}

// FillRequestForHostname fills the given instance of request r for matching the
// hostname.  It uses "http://" as a protocol for request URL and [TypeDocument]
// as request type.
func FillRequestForHostname(r *Request, hostname string) {
	// Do not use fmt.Sprintf or url.URL to achieve better performance.
	// Hostname validation should be performed by the function caller.
	urlStr := "http://" + hostname

	// TODO(d.kolyshev): Make r.URL to be [url.URL], then [url.AppendBinary]
	// on usages.
	r.URL = urlStr
	r.URLLowerCase = urlStr
	r.Hostname = hostname

	r.RequestType = TypeDocument
	r.ThirdParty = false
	r.IsHostnameRequest = true

	if domain := effectiveTLDPlusOne(r.Hostname); domain != "" {
		r.Domain = domain
	} else {
		r.Domain = r.Hostname
	}
}

// effectiveTLDPlusOne is a faster version of [publicsuffix.EffectiveTLDPlusOne]
// that avoids using [fmt.Errorf] when the domain is less than or equal to the
// suffix.
//
// TODO(a.garipov):  Reinspect and consider moving to golibs.
func effectiveTLDPlusOne(hostname string) (domain string) {
	hostnameLen := len(hostname)
	if hostnameLen < 1 {
		return ""
	}

	if hostname[0] == '.' || hostname[hostnameLen-1] == '.' {
		return ""
	}

	suffix, _ := publicsuffix.PublicSuffix(hostname)

	i := hostnameLen - len(suffix) - 1
	if i < 0 || hostname[i] != '.' {
		return ""
	}

	return hostname[1+strings.LastIndex(hostname[:i], "."):]
}
