package proxy

import (
	"net/url"
	"testing"

	"github.com/AdguardTeam/urlfilter/rules"

	"github.com/stretchr/testify/assert"
)

func TestAssumeRequestTypeFromFetchDest(t *testing.T) {
	assert.Equal(t, rules.TypeDocument, assumeRequestTypeFromFetchDest("document"))
	assert.Equal(t, rules.TypeSubdocument, assumeRequestTypeFromFetchDest("iframe"))
	assert.Equal(t, rules.TypeStylesheet, assumeRequestTypeFromFetchDest("style"))
	assert.Equal(t, rules.TypeScript, assumeRequestTypeFromFetchDest("script"))
	assert.Equal(t, rules.TypeMedia, assumeRequestTypeFromFetchDest("video"))
	assert.Equal(t, rules.TypeXmlhttprequest, assumeRequestTypeFromFetchDest("empty"))
}

func TestAssumeRequestTypeFromMediaType(t *testing.T) {
	assert.Equal(t, rules.TypeDocument, assumeRequestTypeFromMediaType("text/html"))
	assert.Equal(t, rules.TypeDocument, assumeRequestTypeFromMediaType("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3"))
	assert.Equal(t, rules.TypeStylesheet, assumeRequestTypeFromMediaType("text/css"))
	assert.Equal(t, rules.TypeScript, assumeRequestTypeFromMediaType("text/javascript"))
}

func TestAssumeRequestTypeFromURL(t *testing.T) {
	u, _ := url.Parse("http://example.org/script.js")
	assert.Equal(t, rules.TypeScript, assumeRequestTypeFromURL(u))

	u, _ = url.Parse("http://example.org/script.css")
	assert.Equal(t, rules.TypeStylesheet, assumeRequestTypeFromURL(u))
}
