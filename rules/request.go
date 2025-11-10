package rules

import (
	"math/bits"
	"net/netip"
	"net/url"
	"strings"
	"unicode"

	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
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

	// URL is the full request URL.  It must not be nil.
	URL *url.URL

	// ClientName is the name to match against $client modifiers, if any.
	ClientName string

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

	// urlData is the bytes of this request URL.
	urlData []byte

	// urlDataLower is the bytes of this request URL in lowercase.
	urlDataLower []byte

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

// NewRequest returns a properly initialized *Request.  u must not be nil.
func NewRequest(u, sourceURL *url.URL, requestType RequestType) (r *Request) {
	r = &Request{
		SourceURL:   netutil.CloneURL(sourceURL),
		URL:         netutil.CloneURL(u),
		RequestType: requestType,
	}

	if r.SourceURL != nil {
		r.SourceHostname = r.SourceURL.Hostname()
	}

	hostname := r.URL.Hostname()
	domain := effectiveTLDPlusOne(hostname)
	if domain != "" {
		r.Domain = domain
	} else {
		r.Domain = hostname
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
// hostname.  It uses [urlutil.SchemeHTTP] as a protocol and [TypeDocument] as a
// request type.
func NewRequestForHostname(hostname string) (r *Request) {
	r = &Request{
		URL: &url.URL{
			Scheme: urlutil.SchemeHTTP,
		},
	}

	FillRequestForHostname(r, hostname)

	return r
}

// FillRequestForHostname fills the given instance of request r for matching the
// hostname.  r must not be nil.
func FillRequestForHostname(r *Request, hostname string) {
	r.URL.Host = hostname

	r.urlData = r.urlData[:0]
	r.urlDataLower = r.urlDataLower[:0]

	r.RequestType = TypeDocument
	r.ThirdParty = false
	r.IsHostnameRequest = true

	if domain := effectiveTLDPlusOne(hostname); domain != "" {
		r.Domain = domain
	} else {
		r.Domain = hostname
	}
}

// MaxURLLength limits the URL length by 4 KiB.  It appears that there can be
// URLs longer than a megabyte, and it makes no sense to go through the whole
// URL.
//
// TODO(a.garipov):  Reinspect.
//
// TODO(a.garipov):  Use [datasize.B]?
const MaxURLLength = 4 * 1024

// AppendURLData fills this request URL data fields, then appends the data to
// the given slice.  If lower is true, the data is appended in lowercase.
// Limits the URL length by 4 KiB. It appears that there can be URLs longer than
// a megabyte, and it makes no sense to go through the whole URL.
func (r *Request) AppendURLData(orig []byte, lower bool) (data []byte) {
	if len(r.urlData) == 0 {
		r.urlData, _ = r.URL.AppendBinary(r.urlData)
	}

	if len(r.urlData) > MaxURLLength {
		r.urlData = r.urlData[:MaxURLLength]
	}

	if !lower {
		return append(orig, r.urlData...)
	}

	if len(r.urlDataLower) == 0 {
		for _, b := range r.urlData {
			r.urlDataLower = append(r.urlDataLower, byte(unicode.ToLower(rune(b))))
		}
	}

	return append(orig, r.urlDataLower...)
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
