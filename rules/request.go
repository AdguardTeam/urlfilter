package rules

import (
	"math/bits"
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// RequestType is the request types enumeration
type RequestType uint32

const (
	// TypeDocument (main frame)
	TypeDocument RequestType = 1 << iota
	// TypeSubdocument (iframe) $subdocument
	TypeSubdocument
	// TypeScript (javascript, etc) $script
	TypeScript
	// TypeStylesheet (css) $stylesheet
	TypeStylesheet
	// TypeObject (flash, etc) $object
	TypeObject
	// TypeImage (any image) $image
	TypeImage
	// TypeXmlhttprequest (ajax/fetch) $xmlhttprequest
	TypeXmlhttprequest
	// TypeMedia (video/music) $media
	TypeMedia
	// TypeFont (any custom font) $font
	TypeFont
	// TypeWebsocket (a websocket connection) $websocket
	TypeWebsocket
	// TypePing (navigator.sendBeacon() or ping attribute on links) $ping
	TypePing
	// TypeOther - any other request type
	TypeOther
)

// Count returns the count of the enabled flags.
func (t RequestType) Count() int {
	return bits.OnesCount32(uint32(t))
}

// Request represents a web filtering request with all it's necessary
// properties.
type Request struct {
	// ClientIP is the IP address to match against $client modifiers.  The
	// default zero value won't be considered.
	ClientIP netip.Addr

	// SourceURL is the full URL of the source.
	SourceURL *url.URL

	// URL is the full request URL.
	URL *url.URL

	// ClientName is the name to match against $client modifiers.  The default
	// empty value won't be considered.
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
	// example "A" or "AAAA".  See [RRValue] for all acceptable constants and
	// their corresponding values.
	DNSType uint16

	// ThirdParty is true if the filtering request should consider $third-party
	// modifier.
	ThirdParty bool

	// IsHostnameRequest means that the request is for a given Hostname, and not
	// for a URL, and we don't really know what protocol it is.  This can be
	// true for DNS requests, for HTTP CONNECT, or for SNI matching.
	IsHostnameRequest bool
}

// NewRequest creates a new instance of "Request" and populates it's fields
func NewRequest(u, sourceURL *url.URL, requestType RequestType) *Request {
	r := Request{
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

	return &r
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

// effectiveTLDPlusOne is a faster version of publicsuffix.EffectiveTLDPlusOne
// that avoids using fmt.Errorf when the domain is less or equal the suffix.
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
