package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/ameshkov/goproxy"

	"github.com/AdguardTeam/urlfilter"
)

var defaultInjectionsHost = "injections.adguard.org"

// Config contains the MITM proxy configuration
type Config struct {
	// CertKeyPair is the X509 cert/key pair that is used in the MITM proxy
	CertKeyPair tls.Certificate

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
	proxyHTTPServer *goproxy.ProxyHttpServer

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
	err = setCA(config.CertKeyPair)
	if err != nil {
		return nil, err
	}

	s.proxyHTTPServer = goproxy.NewProxyHttpServer()
	s.proxyHTTPServer.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	s.proxyHTTPServer.OnRequest().DoFunc(s.onRequest)
	s.proxyHTTPServer.OnResponse().DoFunc(s.onResponse)

	// TODO: TEMPORARY, FIX LOGGING
	s.proxyHTTPServer.Verbose = true
	s.proxyHTTPServer.Logger = log.New(os.Stderr, "proxy", log.LstdFlags)

	return s, nil
}

// ListenAndServe listens on the TCP network address addr
// It always returns a non-nil error.
func (s *Server) ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, s.proxyHTTPServer)
}

// onRequest handles the outgoing HTTP requests
func (s *Server) onRequest(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	session := urlfilter.NewSession(ctx.Session, r)

	ctx.Logf("Saving session %d", ctx.Session)
	ctx.UserData = session

	if session.Request.Hostname == s.InjectionHost {
		return r, s.buildContentScript(session)
	}

	session.Result = s.engine.MatchRequest(session.Request)
	rule := session.Result.GetBasicResult()

	if rule != nil && !rule.Whitelist {
		ctx.Logf("Blocked by %s: %s", rule.String(), session.Request.URL)
		// TODO: Replace with a "CreateBlockedResponse" method of the urlfilter.Engine
		return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusInternalServerError, "Blocked")
	}

	return r, nil
}

// onResponse handles all the responses
func (s *Server) onResponse(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	session, ok := ctx.UserData.(*urlfilter.Session)

	if !ok {
		ctx.Warnf("could not find session %d", ctx.Session)
		return r
	}

	// Update the session -- this will cause requestType re-calc
	session.SetResponse(r)

	// Now once we received the response, we must re-calculate the result
	session.Result = s.engine.MatchRequest(session.Request)
	rule := session.Result.GetBasicResult()
	if rule != nil && !rule.Whitelist {
		ctx.Logf("Blocked by %s: %s", rule.String(), session.Request.URL)
		// TODO: Replace with a "CreateBlockedResponse" method of the urlfilter.Engine
		return goproxy.NewResponse(ctx.Req, goproxy.ContentTypeText, http.StatusInternalServerError, "Blocked")
	}

	if session.Request.RequestType == urlfilter.TypeDocument &&
		session.Result.GetCosmeticOption() != urlfilter.CosmeticOptionNone {
		s.filterHTML(session, ctx)
	}

	return r
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

func setCA(goproxyCa tls.Certificate) error {
	var err error
	if goproxyCa.Leaf, err = x509.ParseCertificate(goproxyCa.Certificate[0]); err != nil {
		return fmt.Errorf("failed to set goproxy CA: %s", err)
	}
	goproxy.GoproxyCa = goproxyCa
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	return nil
}
