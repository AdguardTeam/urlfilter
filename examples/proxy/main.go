package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/gomitmproxy"
	"github.com/AdguardTeam/gomitmproxy/mitm"
	"github.com/AdguardTeam/urlfilter/proxy"
)

func main() {
	log.SetLevel(log.DEBUG)

	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	// READ CERT AND KEY
	tlsCert, err := tls.LoadX509KeyPair("demo.crt", "demo.key")
	if err != nil {
		log.Fatal(err)
	}
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
	config.FiltersPaths = map[int]string{
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
