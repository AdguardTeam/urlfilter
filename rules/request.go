package rules

import (
	"net/url"
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
	RequestType RequestType // request type
	ThirdParty  bool        // true if request is third-party

	// IsHostnameRequest means that the request is for a given Hostname,
	//  and not for a URL, and we don't really know what protocol it is.
	// This can be true for DNS requests, or for HTTP CONNECT, or SNI matching.
	IsHostnameRequest bool

	URL          string // Request URL
	URLLowerCase string // Request URL in lower case
	Hostname     string // Request hostname
	Domain       string // Request domain (eTLD+1)

	// DNSType is the type of the resource record (RR) of a DNS request.
	// See package github.com/miekg/dns for all acceptable constants.
	DNSType uint16

	SourceURL      string // Source URL
	SourceHostname string // Source hostname
	SourceDomain   string // Source domain (eTLD+1)

	SortedClientTags []string // Sorted list of client tags ($ctag)
	ClientIP         string   // Client IP address
	ClientName       string   // Client name
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

	domain, err := publicsuffix.EffectiveTLDPlusOne(r.Hostname)
	if err == nil && domain != "" {
		r.Domain = domain
	} else {
		r.Domain = r.Hostname
	}

	sourceDomain, err := publicsuffix.EffectiveTLDPlusOne(r.SourceHostname)
	if err == nil && sourceDomain != "" {
		r.SourceDomain = sourceDomain
	} else {
		r.SourceDomain = r.SourceHostname
	}

	if r.SourceDomain != "" && r.SourceDomain != r.Domain {
		r.ThirdParty = true
	}

	return &r
}

// NewRequestForHostname creates a new instance of "Request" for matching hostname.
// It uses "http://" as a protocol and TypeDocument as a request type.
func NewRequestForHostname(hostname string) *Request {
	urlStr := (&url.URL{
		Scheme: "http",
		Host:   hostname,
	}).String()

	r := Request{
		RequestType:       TypeDocument,
		URL:               urlStr,
		URLLowerCase:      urlStr,
		Hostname:          hostname,
		ThirdParty:        false,
		IsHostnameRequest: true,
	}

	if domain, err := publicsuffix.EffectiveTLDPlusOne(r.Hostname); err == nil && domain != "" {
		r.Domain = domain
	} else {
		r.Domain = r.Hostname
	}

	return &r
}
