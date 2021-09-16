// Package proxy implements a MITM proxy that uses urlfilter to filter content.
// TODO(ameshkov): extract to a submodule
package proxy

import (
	"fmt"
	"time"

	"github.com/AdguardTeam/urlfilter/filterlist"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/gomitmproxy"
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

	// If true, we will serve the content-script compressed
	// This is useful for the case when the proxy is on a public server,
	// as it saves some data.
	CompressContentScript bool
}

// String - server's configuration description
func (c *Config) String() string {
	str := ""
	str += fmt.Sprintf("Listen addr: %s\n", c.ProxyConfig.ListenAddr.String())
	str += fmt.Sprintf("MITM status: %v\n", c.ProxyConfig.MITMConfig != nil)
	str += fmt.Sprintf("Run as HTTPS proxy: %v\n", c.ProxyConfig.TLSConfig != nil)

	if c.ProxyConfig.Username != "" {
		str += fmt.Sprintf("Proxy auth: %s/%s\n", c.ProxyConfig.Username, c.ProxyConfig.Password)
	}
	if c.ProxyConfig.APIHost != "" {
		str += fmt.Sprintf("API host: %s\n", c.ProxyConfig.APIHost)
	}

	if len(c.FiltersPaths) > 0 {
		str += fmt.Sprintf("Filter lists: %d\n", len(c.FiltersPaths))
		for i, v := range c.FiltersPaths {
			str += fmt.Sprintf("%d: %s\n", i, v)
		}
	}

	return str
}

// Server contains the current server state
type Server struct {
	// the MITM proxy server instance
	proxyServer *gomitmproxy.Proxy

	// filtering engine
	engine *urlfilter.Engine

	// time when the server was created
	createdAt time.Time

	Config // Server configuration
}

// NewServer creates a new instance of the MITM server
func NewServer(config Config) (*Server, error) {
	log.Info("Initializing the proxy server:\n%s", config.String())

	if config.InjectionHost == "" {
		config.InjectionHost = defaultInjectionsHost
	}

	s := &Server{
		createdAt: time.Now(),
		Config:    config,
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

// buildEngine builds a new network engine
func buildEngine(config Config) (*urlfilter.Engine, error) {
	var lists []filterlist.RuleList

	for filterID, path := range config.FiltersPaths {
		list, err := filterlist.NewFileRuleList(filterID, path, false)
		if err != nil {
			return nil, fmt.Errorf("failed to create rule list %d: %s", filterID, err)
		}
		lists = append(lists, list)
	}

	ruleStorage, err := filterlist.NewRuleStorage(lists)
	if err != nil {
		return nil, fmt.Errorf("cannot initialize rule storage: %s", err)
	}

	return urlfilter.NewEngine(ruleStorage), nil
}
