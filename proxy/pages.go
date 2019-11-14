package proxy

import (
	"bytes"
	"net/http"
	"strings"

	"github.com/AdguardTeam/urlfilter/rules"

	"github.com/AdguardTeam/gomitmproxy/proxyutil"

	"github.com/AdguardTeam/golibs/log"
)

type blockedPageParameters struct {
	Hostname string
	RuleText string
}

// buildBlockedPage builds blocked page content
func buildBlockedPage(session *Session, f *rules.NetworkRule) string {
	params := blockedPageParameters{
		Hostname: session.Request.Hostname,
		RuleText: f.Text(),
	}

	var data bytes.Buffer
	if err := blockedPageTmpl.Execute(&data, params); err != nil {
		log.Error("error building blocking page code: %v", err)
		return ""
	}

	return data.String()
}

// newBlockedResponse creates an HTTP response for blocked request
func newBlockedResponse(session *Session, f *rules.NetworkRule) *http.Response {
	html := buildBlockedPage(session, f)
	body := strings.NewReader(html)
	res := proxyutil.NewResponse(http.StatusInternalServerError, body, session.HTTPRequest)
	res.Close = true
	res.Header.Set("Content-Type", "text/html; charset=utf-8")
	return res
}
