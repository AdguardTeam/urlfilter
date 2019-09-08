package proxy

import (
	"bytes"
	"io/ioutil"
	"math"
	"strings"

	"github.com/ameshkov/goproxy"

	"github.com/AdguardTeam/urlfilter"
)

// headBufferSize is the count of bytes where we'll be looking for one of injections points
const headBufferSize = 16 * 1024

// filterHTML replaces the original response with the one where the body is modified
func (s *Server) filterHTML(session *urlfilter.Session, ctx *goproxy.ProxyCtx) {
	r := session.HTTPResponse

	body, err := decodeLatin1(r.Body)
	defer r.Body.Close()

	if err != nil {
		ctx.Warnf("could not read the full body: %s", err)
		return
	}

	index := findBodyInjectionIndex(body)
	if index == -1 {
		return
	}

	// TODO (!!!!): HANDLE CSP PROPERLY
	session.HTTPResponse.Header.Del("Content-Security-Policy")
	session.HTTPResponse.Header.Del("Content-Security-Policy-Report-Only")

	injection := s.buildInjectionCode(session)
	body = body[:index] + injection + body[index:]
	modifiedBody, err := encodeLatin1(body)

	if err != nil {
		// TODO: return error page
		ctx.Warnf("could not encode body: %s", err)
	}

	r.Body = ioutil.NopCloser(bytes.NewReader(modifiedBody))
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
	str := body[index : index+len(match)]
	return strings.EqualFold(str, match)
}
