package proxy

import (
	"bytes"
	"io"
	"net/http"
	"text/template"

	"github.com/AdguardTeam/urlfilter/rules"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/gomitmproxy/proxyutil"
	"github.com/AdguardTeam/urlfilter"
)

// This code is to be injected in the page
const contentScriptCode = `
<script src="//{{.InjectionHostname}}/content-script.js?hostname={{.Hostname}}&option={{.Option}}&ts={{.Timestamp}}"></script>
`

var contentScriptURLTmpl = template.Must(template.New("contentScriptCode").Parse(contentScriptCode))

type contentScriptURLParameters struct {
	Option            rules.CosmeticOption
	Hostname          string
	InjectionHostname string
	Timestamp         int64 // just to avoid caching
}

type contentScriptParameters struct {
	Nonce  string                   // random string that we'll be using as a CSP nonce
	Result urlfilter.CosmeticResult // cosmetic result
}

// buildInjectionCode creates HTML code for the content script injection
func (s *Server) buildInjectionCode(session *Session) string {
	params := contentScriptURLParameters{
		Option:            session.Result.GetCosmeticOption(),
		Hostname:          session.Request.Hostname,
		InjectionHostname: s.InjectionHost,
		Timestamp:         s.createdAt.Unix(),
	}
	var data bytes.Buffer
	if err := contentScriptURLTmpl.Execute(&data, params); err != nil {
		log.Error("error building injection code: %v", err)
		return ""
	}

	return data.String()
}

// buildContentScriptCode executes the content script code template
func (s *Server) buildContentScriptCode(result urlfilter.CosmeticResult) string {
	params := contentScriptParameters{
		Nonce:  "",
		Result: result,
	}

	var data bytes.Buffer
	if err := contentScriptTmpl.Execute(&data, params); err != nil {
		log.Error("error building content script code: %v", err)
		return ""
	}

	return data.String()
}

// buildContentScript builds the content script content
func (s *Server) buildContentScript(session *Session) *http.Response {
	r := session.HTTPRequest
	if r.Method != http.MethodGet {
		return newNotFoundResponse(r)
	}

	hostname := getQueryParameter(r, "hostname")
	option := getQueryParameterUint64(r, "option")
	ts := int64(getQueryParameterUint64(r, "ts"))

	if hostname == "" || option == 0 || ts == 0 {
		return newNotFoundResponse(r)
	}

	if ts == s.createdAt.Unix() && r.Header.Get("If-Modified-Since") != "" {
		// Simply return a 304 Not-Modified response
		res := proxyutil.NewResponse(http.StatusNotModified, nil, r)
		res.Header.Set("Content-Type", "text/javascript; charset=utf-8")

		// re-enable the cache
		enableCache(res)
		return res
	}

	cosmeticResult := s.engine.GetCosmeticResult(hostname, rules.CosmeticOption(option))
	bodyBytes := []byte(s.buildContentScriptCode(cosmeticResult))
	contentLen := len(bodyBytes)

	var bodyReader io.Reader

	if s.CompressContentScript {
		b, err := compressGzip(bodyBytes)
		if err != nil {
			log.Error("failed to compress content script: %v", err)
			return proxyutil.NewErrorResponse(r, err)
		}
		contentLen = b.Len()
		bodyReader = io.NopCloser(b)
	} else {
		bodyReader = bytes.NewReader(bodyBytes)
	}

	res := proxyutil.NewResponse(http.StatusOK, bodyReader, r)
	res.Header.Set("Content-Type", "text/javascript; charset=utf-8")
	res.ContentLength = int64(contentLen)

	if s.CompressContentScript {
		res.Header.Set("Content-Encoding", "gzip")
	}

	// make the browser cache the response
	enableCache(res)
	return res
}
