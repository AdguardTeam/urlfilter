package filterutil_test

import (
	"net/url"
	"testing"

	"github.com/AdguardTeam/urlfilter/filterutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractHostname(t *testing.T) {
	testCases := []struct {
		name string
		in   string
		want string
	}{{
		name: "empty",
		in:   "",
		want: "",
	}, {
		name: "http",
		in:   "http://example.com",
		want: "example.com",
	}, {
		name: "http_port",
		in:   "http://example.com:80",
		want: "example.com",
	}, {
		name: "http_path",
		in:   "http://example.com/",
		want: "example.com",
	}, {
		name: "path",
		in:   "/foo?query=bar",
		want: "",
	}, {
		name: "two_slashes",
		in:   "//foo?query=bar",
		want: "foo",
	}, {
		name: "three_slashes",
		in:   "///foo",
		want: "",
	}, {
		name: "port",
		in:   ":8080",
		want: "",
	}, {
		name: "port_string",
		in:   ":foo",
		want: "",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := filterutil.ExtractHostname(tc.in)
			require.Equal(t, tc.want, got)

			assert.Equal(t, extractHostnameStd(tc.in), got)
		})
	}
}

func BenchmarkExtractHostname(b *testing.B) {
	const (
		exampleURL  = "http://example.com"
		exampleHost = "example.com"
	)

	// Compare custom implementation of hostname extraction against a solution
	// using the standard library.
	b.Run("no_std", func(b *testing.B) {
		b.ReportAllocs()

		var got string

		for i := 0; i < b.N; i++ {
			got = filterutil.ExtractHostname(exampleURL)
		}

		assert.Equal(b, exampleHost, got)
	})

	b.Run("std", func(b *testing.B) {
		b.ReportAllocs()

		var got string

		for i := 0; i < b.N; i++ {
			got = extractHostnameStd(exampleURL)
		}

		assert.Equal(b, exampleHost, got)
	})

	// Most recent results:
	//
	// goos: darwin
	// goarch: arm64
	// pkg: github.com/AdguardTeam/urlfilter/filterutil
	// cpu: Apple M1 Pro
	// BenchmarkExtractHostname/no_std-8               26470028               113.5 ns/op             0 B/op          0 allocs/op
	// BenchmarkExtractHostname/std-8                   2272830               458.8 ns/op           144 B/op          1 allocs/op
}

// extractHostnameStd retrieves hostname from the given URL using standard
// library.
func extractHostnameStd(addr string) (hostname string) {
	u, err := url.Parse(addr)
	if err != nil {
		return ""
	}

	return u.Hostname()
}

func FuzzExtractHostname(f *testing.F) {
	testCases := []string{
		"http://www.example.com/",
		"http://user@www.example.com/",
		"http://user%20space@www.example.com/",
		"http://user:password@www.example.com/",
		"http://user:password@www.example.com/path?query=foo#frag",
		"http:www.example.com/?query=foo",
		"http:%2f%2fwww.example.com/?query=foo+bar",
		"stun:example.com",
		"mailto:user@example.com",
		"magnet:?xt=urn:btih:c12fe1c06bba254a9dc9f519b335aa7c1367a88a",
		"/path?query=http://example",
		"//user@example/path?a=b",
		"http://127.0.0.1/",
		"http://127.0.0.1:80/",
		"http://[2001::1]/",
		"http://[2001:db8:85a3:8d3:1319:8a2e:370:7348]/",
		"https://[2001:db8:85a3:8d3:1319:8a2e:370:7348]:443/",
		"https://[2001:db8:85a3:8d3:1319:8a2e:370:7348]:443/p@th?a=1&b=bar#frag",
	}

	for _, tc := range testCases {
		f.Add(tc)
	}

	f.Fuzz(func(_ *testing.T, input string) {
		_ = filterutil.ExtractHostname(input)
	})
}

func TestIsDomainName(t *testing.T) {
	assert.True(t, filterutil.IsDomainName("1.cc"))
	assert.True(t, filterutil.IsDomainName("1.2.cc"))
	assert.True(t, filterutil.IsDomainName("a.b.cc"))
	assert.True(t, filterutil.IsDomainName("abc.abc.abc"))
	assert.True(t, filterutil.IsDomainName("a-bc.ab--c.abc"))
	assert.True(t, filterutil.IsDomainName("abc.xn--p1ai"))
	assert.True(t, filterutil.IsDomainName("xn--p1ai.xn--p1ai"))
	assert.True(t, filterutil.IsDomainName("cc"))
	assert.True(t, filterutil.IsDomainName("xn--p1ai"))

	assert.False(t, filterutil.IsDomainName("#cc"))
	assert.False(t, filterutil.IsDomainName("a.cc#"))
	assert.False(t, filterutil.IsDomainName("abc.xn--"))
	assert.False(t, filterutil.IsDomainName("abc.xn--asd"))

	assert.False(t, filterutil.IsDomainName(".a.cc"))
	assert.False(t, filterutil.IsDomainName("a.cc."))

	assert.False(t, filterutil.IsDomainName("-a.cc"))
	assert.False(t, filterutil.IsDomainName("a-.cc"))

	assert.False(t, filterutil.IsDomainName("a.1cc"))
	assert.False(t, filterutil.IsDomainName("a.cc1"))
	assert.False(t, filterutil.IsDomainName("a.c"))

	const longLabel = "123456789012345678901234567890123456789012345678901234567890123"
	assert.True(t, filterutil.IsDomainName(longLabel+".cc"))
	assert.False(t, filterutil.IsDomainName(longLabel+"4.cc"))
}
