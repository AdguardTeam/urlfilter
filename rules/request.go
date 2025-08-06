package rules

import (
	"math/bits"
	"net/netip"
	"strings"

	"github.com/AdguardTeam/urlfilter/internal/ufnet"
	"golang.org/x/net/publicsuffix"
)

// maxURLLength limits the URL length by 4 KiB. It appears that there
// can be URLs longer than a megabyte, and it makes no sense to go
// through the whole URL.
const maxURLLength = 4 * 1024

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

	// ClientName is the name to match against $client modifiers.  The default
	// empty value won't be considered.
	ClientName string

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
func NewRequest(url, sourceURL string, requestType RequestType) *Request {
	if len(url) > maxURLLength {
		url = url[:maxURLLength]
	}
	if len(sourceURL) > maxURLLength {
		sourceURL = sourceURL[:maxURLLength]
	}

	r := Request{
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

	return &r
}

// NewRequestForHostname creates a new instance of [Request] for matching the
// hostname.  It uses "http://" as a protocol and [TypeDocument] as a request
// type.
func NewRequestForHostname(hostname string) (r *Request) {
	r = &Request{}
	FillRequestForHostname(r, hostname)

	return r
}

// FillRequestForHostname fills an instance of request r for matching the
// hostname.  It uses "http://" as a protocol for request URL and [TypeDocument]
// as request type.
func FillRequestForHostname(r *Request, hostname string) {
	// Do not use fmt.Sprintf or url.URL to achieve better performance.
	// Hostname validation should be performed by the function caller.
	urlStr := "http://" + hostname

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
