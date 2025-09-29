package rules_test

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
)

func TestNewRequest(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		want      *rules.Request
		name      string
		sourceURL string
		url       string
	}{{
		want: &rules.Request{
			ClientIP:          netip.Addr{},
			ClientName:        "",
			URL:               testURLStr,
			URLLowerCase:      testURLStr,
			Hostname:          testHostname,
			Domain:            testHostname,
			SourceURL:         "",
			SourceHostname:    "",
			SourceDomain:      "",
			SortedClientTags:  nil,
			RequestType:       rules.TypeOther,
			DNSType:           0,
			ThirdParty:        false,
			IsHostnameRequest: false,
		},
		name:      "no_source",
		sourceURL: "",
		url:       testURLStr,
	}, {
		want: &rules.Request{
			ClientIP:          netip.Addr{},
			ClientName:        "",
			URL:               testURLStr,
			URLLowerCase:      testURLStr,
			Hostname:          testHostname,
			Domain:            testHostname,
			SourceURL:         testURLSubStr,
			SourceHostname:    testHostnameSub,
			SourceDomain:      testHostname,
			SortedClientTags:  nil,
			RequestType:       rules.TypeOther,
			DNSType:           0,
			ThirdParty:        false,
			IsHostnameRequest: false,
		},
		name:      "source",
		sourceURL: testURLSubStr,
		url:       testURLStr,
	}, {
		want: &rules.Request{
			ClientIP:          netip.Addr{},
			ClientName:        "",
			URL:               testURLLongTLDStr,
			URLLowerCase:      testURLLongTLDStr,
			Hostname:          testHostnameLongTLD,
			Domain:            testHostnameLongTLD,
			SourceURL:         "",
			SourceHostname:    "",
			SourceDomain:      "",
			SortedClientTags:  nil,
			RequestType:       rules.TypeOther,
			DNSType:           0,
			ThirdParty:        false,
			IsHostnameRequest: false,
		},
		name:      "long_tld",
		sourceURL: "",
		url:       testURLLongTLDStr,
	}, {
		want: &rules.Request{
			ClientIP:          netip.Addr{},
			ClientName:        "",
			URL:               testURLStr,
			URLLowerCase:      testURLStr,
			Hostname:          testHostname,
			Domain:            testHostname,
			SourceURL:         testURLLongTLDStr,
			SourceHostname:    testHostnameLongTLD,
			SourceDomain:      testHostnameLongTLD,
			SortedClientTags:  nil,
			RequestType:       rules.TypeOther,
			DNSType:           0,
			ThirdParty:        true,
			IsHostnameRequest: false,
		},
		name:      "third_party",
		sourceURL: testURLLongTLDStr,
		url:       testURLStr,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := rules.NewRequest(tc.url, tc.sourceURL, rules.TypeOther)
			assert.Equal(t, tc.want, req)
		})
	}
}

func TestRequestType_Count(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		rType rules.RequestType
		want  int
	}{{
		rType: rules.TypeDocument,
		want:  1,
	}, {
		rType: rules.TypeDocument | rules.TypeOther,
		want:  2,
	}, {
		rType: rules.TypeDocument | rules.TypeOther | rules.TypeImage | rules.TypeFont,
		want:  4,
	}, {
		rType: 0,
		want:  0,
	}}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("flags_%v", tc.want), func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.rType.Count(), tc.want)
		})
	}
}

func TestFillRequestForHostname(t *testing.T) {
	t.Parallel()

	req := rules.NewRequest("http://other.example/", "", rules.TypeOther)

	rules.FillRequestForHostname(req, testHostname)
	assert.Equal(t, &rules.Request{
		ClientIP:          netip.Addr{},
		ClientName:        "",
		URL:               testURLStr,
		URLLowerCase:      testURLStr,
		Hostname:          testHostname,
		Domain:            testHostname,
		SourceURL:         "",
		SourceHostname:    "",
		SourceDomain:      "",
		SortedClientTags:  nil,
		RequestType:       rules.TypeDocument,
		DNSType:           0,
		ThirdParty:        false,
		IsHostnameRequest: true,
	}, req)
}

func BenchmarkFillRequestForHostname(b *testing.B) {
	req := &rules.Request{}

	b.ReportAllocs()
	for b.Loop() {
		rules.FillRequestForHostname(req, testHostname)
	}

	assert.Equal(b, &rules.Request{
		ClientIP:          netip.Addr{},
		ClientName:        "",
		URL:               testURLStr,
		URLLowerCase:      testURLStr,
		Hostname:          testHostname,
		Domain:            testHostname,
		SourceURL:         "",
		SourceHostname:    "",
		SourceDomain:      "",
		SortedClientTags:  nil,
		RequestType:       rules.TypeDocument,
		DNSType:           0,
		ThirdParty:        false,
		IsHostnameRequest: true,
	}, req)

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/urlfilter/rules
	//	cpu: Apple M1 Pro
	//	BenchmarkFillRequestForHostname-8   	10298487	       109.2 ns/op	      24 B/op	       1 allocs/op
}
