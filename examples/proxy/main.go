package main

import (
	"crypto/tls"
	"io/ioutil"

	"github.com/AdguardTeam/urlfilter/proxy"

	"log"
)

func main() {
	cert, err := ioutil.ReadFile("demo.crt")
	if err != nil {
		panic(err)
	}
	key, err := ioutil.ReadFile("demo.key")
	if err != nil {
		panic(err)
	}
	ca, err := tls.X509KeyPair(cert, key)
	if err != nil {
		panic(err)
	}

	config := proxy.Config{}
	config.CertKeyPair = ca
	config.FiltersPaths = map[int]string{1: "easylist.txt"}

	server, err := proxy.NewServer(config)
	if err != nil {
		panic(err)
	}

	log.Fatal(server.ListenAndServe(":8080"))
}
