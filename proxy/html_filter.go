package proxy

import (
	"bytes"
	"io/ioutil"
	"math"
	"strings"
	"text/template"
	"time"

	"github.com/ameshkov/goproxy"

	"github.com/AdguardTeam/urlfilter"
)

// headBufferSize is the count of bytes where we'll be looking for one of injections points
const headBufferSize = 16 * 1024
const contentScriptURL = `
<script src="//{{.InjectionHostname}}/content-script.js?hostname={{.Hostname}}&option={{.Option}}&ts={{.Timestamp}}"></script>
`

var timestamp = time.Now().Unix()
var contentScriptURLTmpl = template.Must(template.New("contentScriptURL").Parse(contentScriptURL))

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
