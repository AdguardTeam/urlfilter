package proxy

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/require"
)

// testURL is the common URL value for tests.
var testURL = &url.URL{
	Scheme: urlutil.SchemeHTTPS,
	Host:   "example.org",
}

func TestAssumeRequestType(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		headers      http.Header
		response     *http.Response
		name         string
		expectedType rules.RequestType
	}{{
		name: "sec-fetch-dest-video",
		headers: http.Header{
			"Sec-Fetch-Dest": {"video"},
		},
		expectedType: rules.TypeMedia,
	}, {
		name: "upgrade-websocket",
		headers: http.Header{
			"Upgrade": {"websocket"},
		},
		expectedType: rules.TypeWebsocket,
	}, {
		name: "ping-header",
		headers: http.Header{
			"Ping-To": {"https://example.org"},
		},
		expectedType: rules.TypePing,
	}, {
		name: "html-content-type",
		response: &http.Response{
			Header: http.Header{"Content-Type": {"text/html"}},
		},
		expectedType: rules.TypeDocument,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, testURL.String(), nil)
			maps.Copy(req.Header, tc.headers)

			// Now check that
			resourceType := assumeRequestType(req, tc.response)
			require.Equal(t, tc.expectedType, resourceType)
		})
	}
}

func TestAssumeRequestTypeFromFetchDest(t *testing.T) {
	t.Parallel()

	require.Equal(t, rules.TypeDocument, assumeRequestTypeFromFetchDest("document"))
	require.Equal(t, rules.TypeSubdocument, assumeRequestTypeFromFetchDest("iframe"))
	require.Equal(t, rules.TypeStylesheet, assumeRequestTypeFromFetchDest("style"))
	require.Equal(t, rules.TypeScript, assumeRequestTypeFromFetchDest("script"))
	require.Equal(t, rules.TypeMedia, assumeRequestTypeFromFetchDest("video"))
	require.Equal(t, rules.TypeXmlhttprequest, assumeRequestTypeFromFetchDest("empty"))
}

func TestAssumeRequestTypeFromMediaType(t *testing.T) {
	t.Parallel()

	require.Equal(t, rules.TypeDocument, assumeRequestTypeFromMediaType("text/html"))
	require.Equal(t, rules.TypeDocument, assumeRequestTypeFromMediaType("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3"))
	require.Equal(t, rules.TypeStylesheet, assumeRequestTypeFromMediaType("text/css"))
	require.Equal(t, rules.TypeScript, assumeRequestTypeFromMediaType("text/javascript"))
}

func TestAssumeRequestTypeFromURL(t *testing.T) {
	t.Parallel()

	u, _ := url.Parse("http://example.org/script.js")
	require.Equal(t, rules.TypeScript, assumeRequestTypeFromURL(u))

	u, _ = url.Parse("http://example.org/script.css")
	require.Equal(t, rules.TypeStylesheet, assumeRequestTypeFromURL(u))
}
