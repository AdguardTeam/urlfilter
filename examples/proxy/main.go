package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"log"

	"github.com/AdguardTeam/urlfilter"
	"github.com/ameshkov/goproxy"
)

func main() {
	flag.Parse()
	err := setRootCA()
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
	list, err := urlfilter.NewFileRuleList(1, "easylist.txt", false)
	if err != nil {
		panic(err)
	}
	lists := []urlfilter.RuleList{list}
	ruleStorage, err := urlfilter.NewRuleStorage(lists)
	if err != nil {
		panic(fmt.Sprintf("cannot initialize rule storage: %s", err))
	}

	return urlfilter.NewNetworkEngine(ruleStorage)
}
