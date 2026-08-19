// Deprecated: since proxy package is deprecated, this package will be removed
// in the near future.
package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil/httputil"

	//lint:ignore SA1019 See AGH-21.
	"github.com/AdguardTeam/gomitmproxy"
	"github.com/AdguardTeam/gomitmproxy/mitm"

	//lint:ignore SA1019 See AGH-21.
	"github.com/AdguardTeam/urlfilter/proxy"
	"github.com/AdguardTeam/urlfilter/rules"
)

func main() {
	log.SetLevel(log.DEBUG)

	go func() {
		addr, err := netip.ParseAddr("127.0.0.1")
		if err != nil {
			log.Fatal(err)
		}
		srv := httputil.NewServer(&httputil.ServerConfig{
			Server: &http.Server{
				ReadTimeout:  10 * time.Second,
				WriteTimeout: 10 * time.Second,
			},
			InitialAddress: netip.AddrPortFrom(
				addr,
				6060,
			),
		})

		ctx := context.Background()
		log.Println(srv.Start(ctx))
	}()

	// READ CERT AND KEY
	tlsCert, err := tls.LoadX509KeyPair("demo.crt", "demo.key")
	if err != nil {
		log.Fatal(err)
	}

	// TODO(a.garipov):  Return an error of the certificate isn't RSA.
	privateKey := tlsCert.PrivateKey.(*rsa.PrivateKey)

	x509c, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}

	mitmConfig, err := mitm.NewConfig(x509c, privateKey, nil)
	if err != nil {
		log.Fatal(err)
	}

	mitmConfig.SetValidity(time.Hour * 24 * 7) // generate certs valid for 7 days
	mitmConfig.SetOrganization("gomitmproxy")  // cert organization

	// GENERATE A CERT FOR HTTP OVER TLS PROXY
	proxyCert, err := mitmConfig.GetOrCreateCert("127.0.0.1")
	if err != nil {
		panic(err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*proxyCert},
		// gosec is triggered when the TLS version is set to less than 1.2.
		MinVersion: tls.VersionTLS12,
	}

	addr := &net.TCPAddr{
		IP:   net.IPv4(0, 0, 0, 0),
		Port: 3333,
	}

	config := proxy.Config{
		CompressContentScript: true,
	}
	config.ProxyConfig = gomitmproxy.Config{
		ListenAddr: addr,
		TLSConfig:  tlsConfig,

		Username: "user",
		Password: "pass",
		APIHost:  "gomitmproxy",

		MITMConfig:     mitmConfig,
		MITMExceptions: []string{"example.com"},
	}
	config.FiltersPaths = map[rules.ListID]string{
		1: "adguard_base_filter.txt",
		2: "adguard_russian_filter.txt",
	}

	server, err := proxy.NewServer(config)
	if err != nil {
		panic(err)
	}

	err = server.Start()
	if err != nil {
		log.Fatal(err)
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel

	// CLOSE THE PROXY
	server.Close()
}
