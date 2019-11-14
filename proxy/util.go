package proxy

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"strconv"

	"github.com/AdguardTeam/gomitmproxy/proxyutil"
)

// compresses the specified byte array
func compressGzip(toCompress []byte) (*bytes.Buffer, error) {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write(toCompress); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return &b, nil
}

func newNotFoundResponse(r *http.Request) *http.Response {
	res := proxyutil.NewResponse(http.StatusNotFound, nil, r)
	res.Header.Set("Content-Type", "text/html")
	return res
}

func getQueryParameter(r *http.Request, name string) string {
	params, ok := r.URL.Query()[name]
	if !ok || len(params) != 1 {
		return ""
	}
	return params[0]
}

func getQueryParameterUint64(r *http.Request, name string) uint64 {
	str := getQueryParameter(r, name)
	val, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		return 0
	}
	return val
}
