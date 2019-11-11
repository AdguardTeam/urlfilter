package proxy

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/gomitmproxy"
	"github.com/AdguardTeam/gomitmproxy/proxyutil"
	"github.com/AdguardTeam/urlfilter"
)

const sessionPropKey = "session"
const requestBlockedKey = "blocked"

var defaultInjectionsHost = "injections.adguard.org"

// Config contains the MITM proxy configuration
type Config struct {
	// Config of the MITM proxy
	ProxyConfig gomitmproxy.Config

	// Paths to the filtering rules
	FiltersPaths map[int]string

	// InjectionHost is used for injecting custom CSS/JS into web pages.
	//
	// Here's how it works:
	// * The proxy injects `<script src="//INJECTIONS_HOST/content-script.js?domain=HOSTNAME&flags=FLAGS"></script>`
	// * Depending on the FLAGS and the HOSTNAME, it either injects cosmetic rules or not
	// * Proxy handles requests to this host
	// * The content script content depends on the FLAGS value
	InjectionHost string
}

// Server contains the current server state
type Server struct {
	// the MITM proxy server instance
	proxyServer *gomitmproxy.Proxy

	// filtering engine
	engine *urlfilter.Engine

	Config // Server configuration
}

// NewServer creates a new instance of the MITM server
func NewServer(config Config) (*Server, error) {
	if config.InjectionHost == "" {
		config.InjectionHost = defaultInjectionsHost
	}

	s := &Server{
		Config: config,
	}

	engine, err := buildEngine(config)
	if err != nil {
		return nil, err
	}

	s.engine = engine
	s.ProxyConfig.OnRequest = s.onRequest
	s.ProxyConfig.OnResponse = s.onResponse
	s.ProxyConfig.OnConnect = s.onConnect
	s.proxyServer = gomitmproxy.NewProxy(s.ProxyConfig)
	return s, nil
}

// Start starts the proxy server
func (s *Server) Start() error {
	return s.proxyServer.Start()
}

// Close stops the proxy server
func (s *Server) Close() {
	s.proxyServer.Close()
}

// onRequest handles the outgoing HTTP requests
func (s *Server) onRequest(sess *gomitmproxy.Session) (*http.Request, *http.Response) {
	r := sess.Request()
	session := NewSession(sess.ID(), r)

	log.Debug("urlfilter: id=%s: saving session", session.ID)
	sess.SetProp(sessionPropKey, session)

	// TODO: handle it in gomitmproxy properly
	if r.Method == http.MethodConnect {
		return nil, nil
	}

	if session.Request.Hostname == s.InjectionHost {
		return r, s.buildContentScript(session)
	}

	session.Result = s.engine.MatchRequest(session.Request)
	rule := session.Result.GetBasicResult()

	if rule != nil && !rule.Whitelist {
		log.Debug("urlfilter: id=%s: blocked by %s: %s", session.ID, rule.String(), session.Request.URL)

		// TODO: Replace with a "CreateBlockedResponse" method of the urlfilter.Engine
		body := strings.NewReader("Blocked")
		res := proxyutil.NewResponse(http.StatusInternalServerError, body, r)
		res.Close = true

		// Mark this request as blocked so that we didn't modify it in the onResponse handler
		sess.SetProp(requestBlockedKey, true)
		return nil, res
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

		// TODO: Replace with a "CreateBlockedResponse" method of the urlfilter.Engine
		body := strings.NewReader("Blocked")
		res := proxyutil.NewResponse(http.StatusInternalServerError, body, sess.Request())
		res.Close = true

		return res
	}

	if session.Request.RequestType == urlfilter.TypeDocument &&
		session.Result.GetCosmeticOption() != urlfilter.CosmeticOptionNone {
		s.filterHTML(session)
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

// buildEngine builds a new network engine
func buildEngine(config Config) (*urlfilter.Engine, error) {
	var lists []urlfilter.RuleList

	for filterID, path := range config.FiltersPaths {
		list, err := urlfilter.NewFileRuleList(filterID, path, false)
		if err != nil {
			return nil, fmt.Errorf("failed to create rule list %d: %s", filterID, err)
		}
		lists = append(lists, list)
	}

	ruleStorage, err := urlfilter.NewRuleStorage(lists)
	if err != nil {
		return nil, fmt.Errorf("cannot initialize rule storage: %s", err)
	}

	return urlfilter.NewEngine(ruleStorage), nil
}
