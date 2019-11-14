package proxy

import (
	"net"
	"net/http"

	"github.com/AdguardTeam/urlfilter/rules"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/gomitmproxy"
	"github.com/AdguardTeam/gomitmproxy/proxyutil"
)

// onRequest handles the outgoing HTTP requests
func (s *Server) onRequest(sess *gomitmproxy.Session) (*http.Request, *http.Response) {
	r := sess.Request()
	session := NewSession(sess.ID(), r)

	log.Debug("urlfilter: id=%s: saving session", session.ID)
	sess.SetProp(sessionPropKey, session)

	if r.Method == http.MethodConnect {
		// Do nothing for CONNECT requests
		return nil, nil
	}

	if session.Request.Hostname == s.InjectionHost {
		return r, s.buildContentScript(session)
	}

	session.Result = s.engine.MatchRequest(session.Request)
	rule := session.Result.GetBasicResult()

	if rule != nil && !rule.Whitelist {
		log.Debug("urlfilter: id=%s: blocked by %s: %s", session.ID, rule.String(), session.Request.URL)

		// Mark this request as blocked so that we didn't modify it in the onResponse handler
		sess.SetProp(requestBlockedKey, true)

		return nil, newBlockedResponse(session, rule)
	}

	if s.shouldSuppressCache(session) {
		suppressCache(r)
	}

	return r, nil
}

// onResponse handles all the responses
func (s *Server) onResponse(sess *gomitmproxy.Session) *http.Response {
	if _, ok := sess.GetProp(requestBlockedKey); ok {
		// request was already blocked
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

	// Update the session -- this will cause requestType re-calc
	session.SetResponse(sess.Response())

	// Now once we received the response, we must re-calculate the result
	session.Result = s.engine.MatchRequest(session.Request)
	rule := session.Result.GetBasicResult()
	if rule != nil && !rule.Whitelist {
		log.Debug("urlfilter: id=%s: blocked by %s: %s", session.ID, rule.String(), session.Request.URL)
		return newBlockedResponse(session, rule)
	}

	if session.Request.RequestType == rules.TypeDocument &&
		session.Result.GetCosmeticOption() != rules.CosmeticOptionNone {
		err := s.filterHTML(session)
		if err != nil {
			return proxyutil.NewErrorResponse(session.HTTPRequest, err)
		}
		return session.HTTPResponse
	}

	return nil
}

// onConnect - the only purpose is to intercept and suppress connections to InjectionHost
func (s *Server) onConnect(session *gomitmproxy.Session, proto string, addr string) net.Conn {
	host, _, err := net.SplitHostPort(addr)

	if err == nil && host == s.InjectionHost {
		return &proxyutil.NoopConn{}
	}

	return nil
}
