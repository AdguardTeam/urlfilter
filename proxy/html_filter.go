package proxy

import (
	"bytes"
	"io/ioutil"
	"math"
	"strings"

	"github.com/AdguardTeam/gomitmproxy/proxyutil"

	"github.com/prometheus/common/log"

	"github.com/AdguardTeam/urlfilter"
)

// headBufferSize is the count of bytes where we'll be looking for one of injections points
const headBufferSize = 16 * 1024

// filterHTML replaces the original response with the one where the body is modified
// TODO: Make it return error and handle it from the outside
func (s *Server) filterHTML(session *urlfilter.Session) {
	res := session.HTTPResponse
	req := session.HTTPRequest

	b, err := proxyutil.ReadDecompressedBody(res)
	// Close the original body
	_ = res.Body.Close()
	if err != nil {
		log.Errorf("urlfilter id=%s: could not read the full body: %v", session.ID, err)
		session.HTTPResponse = proxyutil.NewErrorResponse(req, err)
		return
	}

	// Use latin1 before modifying the body
	// Using this 1-byte encoding will let us preserve all original characters
	// regardless of what exactly is the encoding
	body, err := proxyutil.DecodeLatin1(bytes.NewReader(b))
	if err != nil {
		log.Errorf("urlfilter id=%s: could not decode the body: %v", session.ID, err)
		session.HTTPResponse = proxyutil.NewErrorResponse(req, err)
		return
	}

	// Modifying the original body
	modifiedBody := body
	index := findBodyInjectionIndex(body)
	if index != -1 {
		// TODO (!!!!): HANDLE CSP PROPERLY
		session.HTTPResponse.Header.Del("Content-Security-Policy")
		session.HTTPResponse.Header.Del("Content-Security-Policy-Report-Only")
		injection := s.buildInjectionCode(session)
		modifiedBody = body[:index] + injection + body[index:]
	}

	b, err = proxyutil.EncodeLatin1(modifiedBody)
	if err != nil {
		log.Errorf("urlfilter id=%s: could not encode body: %v", session.ID, err)
		session.HTTPResponse = proxyutil.NewErrorResponse(req, err)
		return
	}

	res.Body = ioutil.NopCloser(bytes.NewReader(b))
	res.Header.Del("Content-Encoding")
	res.ContentLength = int64(len(b))
}

// findBodyInjectionIndex finds a place where we can inject the content script
func findBodyInjectionIndex(body string) int {
	cnt := int(math.Min(headBufferSize, float64(len(body))))
	for i := 0; i < cnt; i++ {
		if isMatchFound(body, "</head", i) ||
			isMatchFound(body, "<link", i) ||
			isMatchFound(body, "<style", i) ||
			isMatchFound(body, "<script", i) {
			return i
		}
	}

	return -1
}

// isMatchFound checks if body
func isMatchFound(body string, match string, index int) bool {
	if index+len(match) > len(body) {
		return false
	}

	str := body[index : index+len(match)]
	return strings.EqualFold(str, match)
}
