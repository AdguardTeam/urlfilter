package main

import (
	"bufio"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/AdguardTeam/urlfilter"

	"github.com/ameshkov/goproxy"
)

func main() {
	flag.Parse()
	err := setCA(caCert, caKey)
	if err != nil {
		panic(err)
	}

	engine := buildNetworkEngine()

	proxy := goproxy.NewProxyHttpServer()
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxy.OnRequest().DoFunc(
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			// TODO: headers to request type
			req := urlfilter.NewRequest(r.URL.String(), r.Referer(), urlfilter.TypeOther)

			rule, ok := engine.Match(req)
			if ok && !rule.Whitelist {
				ctx.Logf("blocked: %s", req.URL)
				return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusInternalServerError, "Blocked")
			}

			return r, nil
		})

	proxy.Verbose = true
	proxy.Logger = log.New(os.Stderr, "proxy", log.LstdFlags)
	log.Fatal(http.ListenAndServe(":8080", proxy))
}

func buildNetworkEngine() *urlfilter.NetworkEngine {
	file, err := os.Open("easylist.txt")
	if err != nil {
		panic(err)
	}

	var rules []*urlfilter.NetworkRule

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line != "" {

			rule, err := urlfilter.NewNetworkRule(line, 0)
			if err == nil {
				rules = append(rules, rule)
			}
		}
	}

	rulesStorage, err := urlfilter.NewRuleStorage("")
	if err != nil {
		panic(err)
	}

	return urlfilter.NewNetworkEngine(rules, rulesStorage)
}
