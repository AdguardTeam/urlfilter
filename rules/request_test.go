package rules

import (
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
