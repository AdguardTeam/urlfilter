package uftest

import (
	"archive/zip"
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"strings"
	"testing"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/urlfilter/internal/ufnet"
	"github.com/stretchr/testify/require"
)

// Request contains data for a filtering request for tests.
type Request struct {
	URL         string `json:"url"`
	FrameURL    string `json:"frameUrl"`
	RequestType string `json:"cpt"`
}

// RequestHostnames returns a slice of test hostnames taken from the result of
// [ParseRequests].
func RequestHostnames(tb testing.TB) (hostnames []string) {
	tb.Helper()

	for _, req := range ParseRequests(tb) {
		h := ufnet.ExtractHostname(req.URL)
		if h != "" {
			hostnames = append(hostnames, h)
		}
	}

	return hostnames
}

// requestsZIP is the test requests data archived as a ZIP archive.
//
// TODO(a.garipov):  See if a ZIP is necessary at all.
//
//go:embed testdata/requests.json.zip
var requestsZIP []byte

// ParseRequests loads requests for tests from the testdata.
//
// TODO(a.garipov):  Find a way to parse this once.
func ParseRequests(tb testing.TB) (requests []*Request) {
	tb.Helper()

	r, err := zip.NewReader(bytes.NewReader(requestsZIP), int64(len(requestsZIP)))
	require.NoError(tb, err)

	f, err := r.Open("requests.json")
	require.NoError(tb, err)
	defer func() { err = errors.WithDeferred(err, f.Close()) }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		req := &Request{}
		err = json.Unmarshal(line, req)
		require.NoError(tb, err)

		if isSupportedURL(req.URL) && isSupportedURL(req.FrameURL) {
			requests = append(requests, req)
		}
	}

	require.NoError(tb, scanner.Err())

	return requests
}

// isSupportedURL returns true if s contains a URL that is supported by module
// urlfilter.
func isSupportedURL(s string) (ok bool) {
	return s != "" && (strings.HasPrefix(s, "http") || strings.HasPrefix(s, "ws"))
}
