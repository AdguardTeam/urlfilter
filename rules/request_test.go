package rules

import (
	"fmt"
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

func TestRequestType_Count(t *testing.T) {
	testCases := []struct {
		rType RequestType
		want  int
	}{{
		rType: TypeDocument,
		want:  1,
	}, {
		rType: TypeDocument | TypeOther,
		want:  2,
	}, {
		rType: TypeDocument | TypeOther | TypeImage | TypeFont,
		want:  4,
	}, {
		rType: 0,
		want:  0,
	}}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("flags_%v", tc.want), func(t *testing.T) {
			assert.Equal(t, tc.rType.Count(), tc.want)
		})
	}
}

func TestEffectiveTLDPlusOne(t *testing.T) {
	testCases := []struct {
		name     string
		hostname string
		want     string
	}{{
		name:     "simple_domain",
		hostname: "example.org",
		want:     "example.org",
	}, {
		name:     "simple_subdomain",
		hostname: "test.example.org",
		want:     "example.org",
	}, {
		name:     "invalid_domain",
		hostname: ".",
		want:     "",
	}, {
		name:     "invalid_domain_prefix",
		hostname: ".example.org",
		want:     "",
	}, {
		name:     "invalid_domain_suffix",
		hostname: "example.org.",
		want:     "",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, effectiveTLDPlusOne(tc.hostname))
		})
	}
}
