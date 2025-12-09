package uftest

import (
	"archive/zip"
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/stretchr/testify/require"
)

// Request contains data for a filtering request for tests.
type Request struct {
	// FrameURL is the URL of the frame.
	FrameURL *url.URL

	// URL is the URL of the request.  It must not be nil.
	URL *urlutil.URL `json:"url"`

	// FrameURLStr is the URL string of the frame.
	FrameURLStr string `json:"frameUrl"`

	// RequestType is the request type.
	RequestType string `json:"cpt"`
}

// RequestHostnames returns a slice of test hostnames taken from the result of
// [ParseRequests].
func RequestHostnames(tb testing.TB) (hostnames []string) {
	tb.Helper()

	for _, req := range ParseRequests(tb) {
		h := req.URL.Hostname()
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
		if err != nil {
			// Skip requests with invalid data.
			continue
		}

		if req.FrameURLStr != "" {
			req.FrameURL, err = url.Parse(req.FrameURLStr)
			require.NoError(tb, err)
		}

		if isSupportedURL(&req.URL.URL) && isSupportedURL(req.FrameURL) {
			requests = append(requests, req)
		}
	}

	require.NoError(tb, scanner.Err())

	return requests
}

// isSupportedURL returns true if the given URL is supported for tests.  Returns
// true if u is nil.
func isSupportedURL(u *url.URL) (ok bool) {
	if u == nil {
		return true
	}

	scheme := u.Scheme

	// TODO(a.garipov):  Add websocket schemes to golibs.
	return scheme == urlutil.SchemeHTTP ||
		scheme == urlutil.SchemeHTTPS ||
		scheme == "ws" ||
		scheme == "wss"
}
