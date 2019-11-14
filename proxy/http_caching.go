package proxy

import (
	"fmt"
	"net/http"
	"time"

	"github.com/AdguardTeam/urlfilter/rules"
)

// Suppress cache during the first minutes from the startup
const suppressCachePeriodSecs = int64(1 * time.Minute)

var defaultCacheExpirationSecs = int64(time.Hour.Seconds())

// Checks if we should suppress the HTTP cache for the given request
// We do this to make sure that updated content script is injected into the page
func (s *Server) shouldSuppressCache(session *Session) bool {
	if time.Now().Unix()-s.createdAt.Unix() > suppressCachePeriodSecs {
		return false
	}

	r := session.Request

	// Don't suppress cache for static resources
	if r.RequestType == rules.TypeImage ||
		r.RequestType == rules.TypeFont ||
		r.RequestType == rules.TypeScript ||
		r.RequestType == rules.TypeStylesheet ||
		r.RequestType == rules.TypeMedia {
		return false
	}

	return true
}

// suppressCache removes cache headers from the HTTP request
func suppressCache(r *http.Request) {
	// Last modified time based caching
	r.Header.Del("If-Modified-Since")
	r.Header.Del("If-Unmodified-Since")

	// ETag based caching
	r.Header.Del("If-None-Match")
	r.Header.Del("If-Match")
	r.Header.Del("If-Range")
}

// enableCache - sets caching headers on an HTTP response
func enableCache(r *http.Response) {
	expires := time.Now().Add(time.Duration(defaultCacheExpirationSecs) * time.Second)

	r.Header.Del("Pragma")
	r.Header.Set("Last-Modified", "Wed, 01 Jan 2010 01:00:00 GMT")
	r.Header.Set("Cache-Control", fmt.Sprintf("public, max-age=%d", defaultCacheExpirationSecs))
	r.Header.Set("Expires", expires.Format(http.TimeFormat))
}
