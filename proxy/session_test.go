package proxy

import (
	"net/url"
	"testing"

	"github.com/AdguardTeam/urlfilter"
	"github.com/stretchr/testify/assert"
)

func TestAssumeRequestTypeFromMediaType(t *testing.T) {
	assert.Equal(t, urlfilter.TypeDocument, assumeRequestTypeFromMediaType("text/html"))
	assert.Equal(t, urlfilter.TypeDocument, assumeRequestTypeFromMediaType("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3"))
	assert.Equal(t, urlfilter.TypeStylesheet, assumeRequestTypeFromMediaType("text/css"))
	assert.Equal(t, urlfilter.TypeScript, assumeRequestTypeFromMediaType("text/javascript"))
}

func TestAssumeRequestTypeFromURL(t *testing.T) {
	u, _ := url.Parse("http://example.org/script.js")
	assert.Equal(t, urlfilter.TypeScript, assumeRequestTypeFromURL(u))

	u, _ = url.Parse("http://example.org/script.css")
	assert.Equal(t, urlfilter.TypeStylesheet, assumeRequestTypeFromURL(u))
}
