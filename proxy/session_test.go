package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/require"
)

func TestAssumeRequestType(t *testing.T) {
	testCases := []struct {
		method          string
		name            string
		url             string
		headers         map[string]string
		response        bool
		responseHeaders map[string]string
		expectedType    rules.RequestType
	}{{
		name: "sec-fetch-dest-video",
		headers: map[string]string{
			"Sec-Fetch-Dest": "video",
		},
		expectedType: rules.TypeMedia,
	}, {
		name: "upgrade-websocket",
		headers: map[string]string{
			"Upgrade": "websocket",
		},
		expectedType: rules.TypeWebsocket,
	}, {
		name: "ping-header",
		headers: map[string]string{
			"Ping-To": "https://example.org",
		},
		expectedType: rules.TypePing,
	}, {
		name:     "html-content-type",
		response: true,
		responseHeaders: map[string]string{
			"Content-Type": "text/html",
		},
		expectedType: rules.TypeDocument,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Prepare the test HTTP request first.
			method := tc.method
			if method == "" {
				method = http.MethodGet
			}
			u := tc.url
			if u == "" {
				u = "https://example.org/"
			}
			req := httptest.NewRequest(method, u, nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			// If needed, prepare the test HTTP response.
			var res *http.Response
			if tc.response {
				res = &http.Response{
					Header: map[string][]string{},
				}
				for k, v := range tc.responseHeaders {
					res.Header.Set(k, v)
				}
			}

			// Now check that
			resourceType := assumeRequestType(req, res)
			require.Equal(t, tc.expectedType, resourceType)
		})
	}
}

func TestAssumeRequestTypeFromFetchDest(t *testing.T) {
	require.Equal(t, rules.TypeDocument, assumeRequestTypeFromFetchDest("document"))
	require.Equal(t, rules.TypeSubdocument, assumeRequestTypeFromFetchDest("iframe"))
	require.Equal(t, rules.TypeStylesheet, assumeRequestTypeFromFetchDest("style"))
	require.Equal(t, rules.TypeScript, assumeRequestTypeFromFetchDest("script"))
	require.Equal(t, rules.TypeMedia, assumeRequestTypeFromFetchDest("video"))
	require.Equal(t, rules.TypeXmlhttprequest, assumeRequestTypeFromFetchDest("empty"))
}

func TestAssumeRequestTypeFromMediaType(t *testing.T) {
	require.Equal(t, rules.TypeDocument, assumeRequestTypeFromMediaType("text/html"))
	require.Equal(t, rules.TypeDocument, assumeRequestTypeFromMediaType("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3"))
	require.Equal(t, rules.TypeStylesheet, assumeRequestTypeFromMediaType("text/css"))
	require.Equal(t, rules.TypeScript, assumeRequestTypeFromMediaType("text/javascript"))
}

func TestAssumeRequestTypeFromURL(t *testing.T) {
	u, _ := url.Parse("http://example.org/script.js")
	require.Equal(t, rules.TypeScript, assumeRequestTypeFromURL(u))

	u, _ = url.Parse("http://example.org/script.css")
	require.Equal(t, rules.TypeStylesheet, assumeRequestTypeFromURL(u))
}
