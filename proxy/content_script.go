package proxy

import (
	"bytes"
	"net/http"
	"strconv"
	"text/template"
	"time"

	"github.com/ameshkov/goproxy"

	"github.com/AdguardTeam/urlfilter"
)

// This code is to be injected in the page
const contentScriptCode = `
<script src="//{{.InjectionHostname}}/content-script.js?hostname={{.Hostname}}&option={{.Option}}&ts={{.Timestamp}}"></script>
`

var timestamp = time.Now().Unix()
var contentScriptURLTmpl = template.Must(template.New("contentScriptCode").Parse(contentScriptCode))

type contentScriptURLParameters struct {
	Option            urlfilter.CosmeticOption
	Hostname          string
	InjectionHostname string
	Timestamp         int64 // just to avoid caching
}

// buildInjectionCode creates HTML code for the content script injection
func (s *Server) buildInjectionCode(session *urlfilter.Session) string {
	params := contentScriptURLParameters{
		Option:            session.Result.GetCosmeticOption(),
		Hostname:          session.Request.Hostname,
		InjectionHostname: s.InjectionHost,
		Timestamp:         timestamp,
	}
	var data bytes.Buffer
	if err := contentScriptURLTmpl.Execute(&data, params); err != nil {
		return ""
	}

	return data.String()
}

// buildContentScript builds the content script content
func (s *Server) buildContentScript(session *urlfilter.Session) *http.Response {
	// TODO: Handle cache

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

	cosmeticResult := s.engine.GetCosmeticResult(hostname, urlfilter.CosmeticOption(option))
	if len(cosmeticResult.ElementHiding.Generic) == 0 {
		// TODO: Change this
		return newNotFoundResponse(r)
	}

	contentType := "text/javascript; charset=utf-8"
	status := http.StatusOK
	body := "console.log('hello')"
	return goproxy.NewResponse(r, contentType, status, body)
}

func newNotFoundResponse(r *http.Request) *http.Response {
	return goproxy.NewResponse(r, goproxy.ContentTypeHtml, http.StatusNotFound, "Not Found")
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
