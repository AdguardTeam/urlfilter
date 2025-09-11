package rules

import (
	"math/bits"
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

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
	// ClientIP is the IP address to match against $client modifiers, if any.
	ClientIP netip.Addr

	// SourceURL is the full URL of the source.
	SourceURL *url.URL

	// URL is the full request URL.
	URL *url.URL

	// ClientName is the name to match against $client modifiers, if any.
	ClientName string

	// Hostname is the hostname to filter.
	Hostname string

	// Domain is the effective top-level domain of the request with an
	// additional label.
	Domain string

	// SourceHostname is the hostname of the source.
	SourceHostname string

	// SourceDomain is the effective top-level domain of the source with an
	// additional label.
	SourceDomain string

	// SortedClientTags is the list of tags to match against $ctag modifiers.
	SortedClientTags []string

	// RequestType is the type of the filtering request.
	RequestType RequestType

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
//
// TODO(d.kolyshev):  Limit the URL length by 4 KiB. It appears that there
// can be URLs longer than a megabyte, and it makes no sense to go through
// the whole URL.
func NewRequest(u, sourceURL *url.URL, requestType RequestType) (r *Request) {
	r = &Request{
		SourceURL:   sourceURL,
		URL:         u,
		Hostname:    u.Hostname(),
		RequestType: requestType,
	}

	if sourceURL != nil {
		r.SourceHostname = sourceURL.Hostname()
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

// NewRequestForURL creates a new instance of [Request] for matching the URL's
// hostname.  It uses [TypeDocument] as a request type.
func NewRequestForURL(u *url.URL) (r *Request) {
	r = &Request{}
	FillRequestForURL(r, u)

	return r
}

// FillRequestForURL fills the given instance of request r for matching the
// given URL.  It uses [TypeDocument] as request type.
func FillRequestForURL(r *Request, u *url.URL) {
	r.URL = u
	r.Hostname = u.Hostname()

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
