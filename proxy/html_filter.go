package proxy

import (
	"bytes"
	"io/ioutil"

	"github.com/ameshkov/goproxy"

	"github.com/AdguardTeam/urlfilter"
)

// filterHTML replaces the original response with the one where the body is modified
func (s *Server) filterHTML(session *urlfilter.Session, ctx *goproxy.ProxyCtx) {
	r := session.HTTPResponse

	body, err := decodeLatin1(r.Body)
	defer r.Body.Close()

	if err != nil {
		ctx.Warnf("could not read the full body: %s", err)
	}

	ctx.Logf(body)
	body = "<!-- HELLO -->" + body

	modifiedBody, err := encodeLatin1(body)
	if err != nil {
		// TODO: return error page
		ctx.Warnf("could not encode body: %s", err)
	}

	r.Body = ioutil.NopCloser(bytes.NewReader(modifiedBody))
}
