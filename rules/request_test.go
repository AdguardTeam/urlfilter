package rules_test

import (
	"fmt"
	"net/netip"
	"net/url"
	"testing"

	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
)

func TestNewRequest(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		sourceURL *url.URL
		url       *url.URL
		want      *rules.Request
		name      string
	}{{
		sourceURL: nil,
		url:       testURL,
		want: &rules.Request{
			ClientIP:          netip.Addr{},
			ClientName:        "",
			URL:               testURL,
			Hostname:          testHostname,
			Domain:            testHostname,
			SourceURL:         nil,
			SourceHostname:    "",
			SourceDomain:      "",
			SortedClientTags:  nil,
			RequestType:       rules.TypeOther,
			DNSType:           0,
			ThirdParty:        false,
			IsHostnameRequest: false,
		},
		name: "no_source",
	}, {
		sourceURL: testURLSub,
		url:       testURL,
		want: &rules.Request{
			ClientIP:          netip.Addr{},
			ClientName:        "",
			URL:               testURL,
			Hostname:          testHostname,
			Domain:            testHostname,
			SourceURL:         testURLSub,
			SourceHostname:    testHostnameSub,
			SourceDomain:      testHostname,
			SortedClientTags:  nil,
			RequestType:       rules.TypeOther,
			DNSType:           0,
			ThirdParty:        false,
			IsHostnameRequest: false,
		},
		name: "source",
	}, {
		sourceURL: nil,
		url:       testURLLongTLD,
		want: &rules.Request{
			ClientIP:          netip.Addr{},
			ClientName:        "",
			URL:               testURLLongTLD,
			Hostname:          testHostnameLongTLD,
			Domain:            testHostnameLongTLD,
			SourceURL:         nil,
			SourceHostname:    "",
			SourceDomain:      "",
			SortedClientTags:  nil,
			RequestType:       rules.TypeOther,
			DNSType:           0,
			ThirdParty:        false,
			IsHostnameRequest: false,
		},
		name: "long_tld",
	}, {
		sourceURL: testURLLongTLD,
		url:       testURL,
		want: &rules.Request{
			ClientIP:          netip.Addr{},
			ClientName:        "",
			URL:               testURL,
			Hostname:          testHostname,
			Domain:            testHostname,
			SourceURL:         testURLLongTLD,
			SourceHostname:    testHostnameLongTLD,
			SourceDomain:      testHostnameLongTLD,
			SortedClientTags:  nil,
			RequestType:       rules.TypeOther,
			DNSType:           0,
			ThirdParty:        true,
			IsHostnameRequest: false,
		},
		name: "third_party",
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

func TestFillRequestForURL(t *testing.T) {
	t.Parallel()

	req := rules.NewRequest(testURL, nil, rules.TypeOther)

	rules.FillRequestForURL(req, testURL)
	assert.Equal(t, &rules.Request{
		ClientIP:          netip.Addr{},
		ClientName:        "",
		URL:               testURL,
		Hostname:          testHostname,
		Domain:            testHostname,
		SourceURL:         nil,
		SourceHostname:    "",
		SourceDomain:      "",
		SortedClientTags:  nil,
		RequestType:       rules.TypeDocument,
		DNSType:           0,
		ThirdParty:        false,
		IsHostnameRequest: true,
	}, req)
}

func BenchmarkFillRequestForURL(b *testing.B) {
	req := &rules.Request{}

	b.ReportAllocs()
	for b.Loop() {
		rules.FillRequestForURL(req, testURL)
	}

	assert.Equal(b, &rules.Request{
		ClientIP:          netip.Addr{},
		ClientName:        "",
		URL:               testURL,
		Hostname:          testHostname,
		Domain:            testHostname,
		SourceURL:         nil,
		SourceHostname:    "",
		SourceDomain:      "",
		SortedClientTags:  nil,
		RequestType:       rules.TypeDocument,
		DNSType:           0,
		ThirdParty:        false,
		IsHostnameRequest: true,
	}, req)

	// Most recent results:
	//
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/urlfilter/rules
	//	cpu: Apple M1 Pro
	//	BenchmarkFillRequestForURL-8   	16819832	        71.05 ns/op	       0 B/op	       0 allocs/op
}
