package urlfilter

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRequest(t *testing.T) {
	r := NewRequest("http://example.org/", "", TypeOther)
	assert.Equal(t, "example.org", r.Hostname)
	assert.Equal(t, "example.org", r.Domain)
	assert.Equal(t, "http://example.org/", r.URL)
	assert.Equal(t, "", r.SourceURL)
	assert.Equal(t, "", r.SourceHostname)
	assert.Equal(t, "", r.SourceDomain)
	assert.Equal(t, TypeOther, r.RequestType)
	assert.Equal(t, false, r.ThirdParty)

	r = NewRequest("http://example.org/", "http://sub.example.org", TypeOther)
	assert.Equal(t, "example.org", r.Hostname)
	assert.Equal(t, "example.org", r.Domain)
	assert.Equal(t, "http://example.org/", r.URL)
	assert.Equal(t, "http://sub.example.org", r.SourceURL)
	assert.Equal(t, "sub.example.org", r.SourceHostname)
	assert.Equal(t, "example.org", r.SourceDomain)
	assert.Equal(t, TypeOther, r.RequestType)
	assert.Equal(t, false, r.ThirdParty)

	r = NewRequest("http://example.org.uk/", "http://sub.example.org.uk", TypeOther)
	assert.Equal(t, "example.org.uk", r.Hostname)
	assert.Equal(t, "example.org.uk", r.Domain)
	assert.Equal(t, "http://example.org.uk/", r.URL)
	assert.Equal(t, "http://sub.example.org.uk", r.SourceURL)
	assert.Equal(t, "sub.example.org.uk", r.SourceHostname)
	assert.Equal(t, "example.org.uk", r.SourceDomain)
	assert.Equal(t, TypeOther, r.RequestType)
	assert.Equal(t, false, r.ThirdParty)

	r = NewRequest("http://example.org.uk/", "http://sub.example.com", TypeOther)
	assert.Equal(t, "example.org.uk", r.Hostname)
	assert.Equal(t, "example.org.uk", r.Domain)
	assert.Equal(t, "http://example.org.uk/", r.URL)
	assert.Equal(t, "http://sub.example.com", r.SourceURL)
	assert.Equal(t, "sub.example.com", r.SourceHostname)
	assert.Equal(t, "example.com", r.SourceDomain)
	assert.Equal(t, TypeOther, r.RequestType)
	assert.Equal(t, true, r.ThirdParty)
}

func TestCountRequestType(t *testing.T) {
	assert.Equal(t, 1, TypeDocument.Count())
	assert.Equal(t, 2, (TypeDocument | TypeOther).Count())
}

func TestAssumeRequestTypeFromMediaType(t *testing.T) {
	assert.Equal(t, TypeDocument, assumeRequestTypeFromMediaType("text/html"))
	assert.Equal(t, TypeDocument, assumeRequestTypeFromMediaType("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3"))
	assert.Equal(t, TypeStylesheet, assumeRequestTypeFromMediaType("text/css"))
	assert.Equal(t, TypeScript, assumeRequestTypeFromMediaType("text/javascript"))
}

func TestAssumeRequestTypeFromURL(t *testing.T) {
	u, _ := url.Parse("http://example.org/script.js")
	assert.Equal(t, TypeScript, assumeRequestTypeFromURL(u))

	u, _ = url.Parse("http://example.org/script.css")
	assert.Equal(t, TypeStylesheet, assumeRequestTypeFromURL(u))
}
