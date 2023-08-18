package rules

import (
	"strings"

	"github.com/AdguardTeam/urlfilter/filterutil"
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

// Count returns count of the enabled flags
func (t RequestType) Count() int {
	if t == 0 {
		return 0
	}

	flags := uint32(t)
	count := 0
	var i uint
	for i = 0; i < 32; i++ {
		mask := uint32(1 << i)
		if (flags & mask) == mask {
			count++
		}
	}
	return count
}

// Request represents a web request with all it's necessary properties
type Request struct {
	// URL is the request URL.
	URL string

	// URLLowerCase is the request URL in lower case.
	URLLowerCase string

	// Hostname is the request hostname.
	Hostname string

	// Domain is the request domain (eTLD+1).
	Domain string

	// SourceURL is the source URL.
	SourceURL string

	// SourceHostname is the source hostname.
	SourceHostname string

	// SourceDomain is the source domain (eTLD+1).
	SourceDomain string

	// ClientIP is the client IP address.
	ClientIP string

	// ClientName is the client name.
	ClientName string

	// SortedClientTags is the sorted list of client tags ($ctag).
	SortedClientTags []string

	// RequestType is the type of the request.
	RequestType RequestType

	// DNSType is the type of the resource record (RR) of a DNS request.  See
	// package github.com/miekg/dns for all acceptable constants.
	DNSType uint16

	// ThirdParty is true if request is third-party.
	ThirdParty bool

	// IsHostnameRequest means that the request is for a given Hostname, and not
	// for a URL, and we don't really know what protocol it is.  This can be
	// true for DNS requests, or for HTTP CONNECT, or SNI matching.
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
		Hostname:     filterutil.ExtractHostname(url),

		SourceURL:      sourceURL,
		SourceHostname: filterutil.ExtractHostname(sourceURL),
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

// NewRequestForHostname creates a new instance of "Request" for matching a
// hostname.  It uses "http://" as a protocol and TypeDocument as a request
// type.
func NewRequestForHostname(hostname string) (r *Request) {
	// Do not use fmt.Sprintf or url.URL to achieve better performance.
	// Hostname validation should be performed by the function caller.
	urlStr := "http://" + hostname

	r = &Request{
		RequestType:       TypeDocument,
		URL:               urlStr,
		URLLowerCase:      urlStr,
		Hostname:          hostname,
		ThirdParty:        false,
		IsHostnameRequest: true,
	}

	if domain := effectiveTLDPlusOne(r.Hostname); domain != "" {
		r.Domain = domain
	} else {
		r.Domain = r.Hostname
	}

	return r
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
