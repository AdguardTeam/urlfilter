package proxy

import (
	"net"
	"net/http"

	"github.com/AdguardTeam/urlfilter/rules"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/gomitmproxy"
	"github.com/AdguardTeam/gomitmproxy/proxyutil"
)

// onRequest handles the outgoing HTTP requests.  sess must not be nil.
func (s *Server) onRequest(sess *gomitmproxy.Session) (req *http.Request, resp *http.Response) {
	r := sess.Request()
	session := NewSession(sess.ID(), r)

	log.Debug("urlfilter: id=%s: saving session", session.ID)
	sess.SetProp(sessionPropKey, session)

	if r.Method == http.MethodConnect {
		// Do nothing for CONNECT requests.
		return nil, nil
	}

	if session.Request.Hostname == s.InjectionHost {
		return r, s.buildContentScript(session)
	}

	session.Result = s.engine.MatchRequest(session.Request)
	rule := session.Result.GetBasicResult()

	if rule != nil && !rule.Whitelist {
		log.Debug("urlfilter: id=%s: blocked by %s: %s", session.ID, rule.String(), session.Request.URL)

		// Mark this request as blocked so that we didn't modify it in the
		// onResponse handler.
		sess.SetProp(requestBlockedKey, true)

		return nil, newBlockedResponse(session, rule)
	}

	if s.shouldSuppressCache(session) {
		suppressCache(r)
	}

	return r, nil
}

// onResponse handles all the responses.  sess must not be nil.
func (s *Server) onResponse(sess *gomitmproxy.Session) (res *http.Response) {
	if _, ok := sess.GetProp(requestBlockedKey); ok {
		// request was already blocked
		return nil
	}

	if sess.Request().Method == http.MethodConnect {
		// Do nothing for CONNECT requests
		return nil
	}

	v, ok := sess.GetProp(sessionPropKey)
	if !ok {
		log.Error("urlfilter: id=%s: session not found", sess.ID())

		return nil
	}

	session, ok := v.(*Session)

	if !ok {
		log.Error("urlfilter: id=%s: session not found (wrong type)", sess.ID())

		return nil
	}

	session.SetResponse(sess.Response())

	session.Result = s.engine.MatchRequest(session.Request)
	rule := session.Result.GetBasicResult()
	if rule != nil && !rule.Whitelist {
		log.Debug("urlfilter: id=%s: blocked by %s: %s", session.ID, rule.String(), session.Request.URL)

		return newBlockedResponse(session, rule)
	}

	return s.applyHTMLFiltering(session)
}

// applyHTMLFiltering applies HTML filtering to documents and subdocuments.
// It Returns a modified response if filtering was applied, nil otherwise.
// session must not be nil.
func (s *Server) applyHTMLFiltering(session *Session) (resp *http.Response) {
	rt := session.Request.RequestType
	if (rt == rules.TypeDocument || rt == rules.TypeSubdocument) &&
		session.Result.GetCosmeticOption() != rules.CosmeticOptionNone {
		err := s.filterHTML(session)
		if err != nil {
			return proxyutil.NewErrorResponse(session.HTTPRequest, err)
		}

		return session.HTTPResponse
	}

	return nil
}

// onConnect intercepts and suppresses connections to injection host.
func (s *Server) onConnect(_ *gomitmproxy.Session, proto, addr string) (conn net.Conn) {
	host, _, err := net.SplitHostPort(addr)

	if err == nil && host == s.InjectionHost {
		return &proxyutil.NoopConn{}
	}

	return nil
}
