package proxy

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"
	"text/template"

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
	Option            urlfilter.CosmeticOption
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
	// TODO: Handle cache

	r := session.HTTPRequest
	if r.Method != http.MethodGet {
		return newNotFoundResponse(r)
	}

	// if r.Header.Get("If-Modified-Since")

	hostname := getQueryParameter(r, "hostname")
	option := getQueryParameterUint64(r, "option")
	ts := int64(getQueryParameterUint64(r, "ts"))

	if hostname == "" || option == 0 || ts == 0 {
		return newNotFoundResponse(r)
	}

	cosmeticResult := s.engine.GetCosmeticResult(hostname, urlfilter.CosmeticOption(option))
	body := s.buildContentScriptCode(cosmeticResult)

	res := proxyutil.NewResponse(http.StatusOK, strings.NewReader(body), r)
	res.Header.Set("Content-Type", "text/javascript; charset=utf-8")
	return res
}

func newNotFoundResponse(r *http.Request) *http.Response {
	res := proxyutil.NewResponse(http.StatusNotFound, nil, r)
	res.Header.Set("Content-Type", "text/html")
	return res
}

func getQueryParameter(r *http.Request, name string) string {
	params, ok := r.URL.Query()[name]
	if !ok || len(params) != 1 {
		return ""
	}
	return params[0]
}

func getQueryParameterUint64(r *http.Request, name string) uint64 {
	str := getQueryParameter(r, name)
	val, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		return 0
	}
	return val
}
