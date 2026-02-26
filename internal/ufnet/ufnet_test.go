package ufnet_test

import (
	"net/url"
	"testing"

	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/urlfilter/internal/ufnet"
	"github.com/AdguardTeam/urlfilter/internal/uftest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractHostname(t *testing.T) {
	t.Parallel()

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
		in:   uftest.URLStrHost,
		want: uftest.Host,
	}, {
		name: "http_port",
		in:   uftest.URLStrHost + ":80",
		want: uftest.Host,
	}, {
		name: "http_path",
		in:   uftest.URLStrHost + "/",
		want: uftest.Host,
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
			t.Parallel()

			got := ufnet.ExtractHostname(tc.in)
			require.Equal(t, tc.want, got)

			assert.Equal(t, extractHostnameStd(tc.in), got)
		})
	}
}

func BenchmarkExtractHostname(b *testing.B) {
	// Compare custom implementation of hostname extraction against a solution
	// using the standard library.
	b.Run("no_std", func(b *testing.B) {
		var got string

		b.ReportAllocs()
		for b.Loop() {
			got = ufnet.ExtractHostname(uftest.URLStrHost)
		}

		assert.Equal(b, uftest.Host, got)
	})

	b.Run("std", func(b *testing.B) {
		var got string

		b.ReportAllocs()
		for b.Loop() {
			got = extractHostnameStd(uftest.URLStrHost)
		}

		assert.Equal(b, uftest.Host, got)
	})

	// Most recent results:
	//
	// goos: linux
	// goarch: amd64
	// pkg: github.com/AdguardTeam/urlfilter/internal/ufnet
	// cpu: Intel(R) Core(TM) i7-10510U CPU @ 1.80GHz
	// BenchmarkExtractHostname/no_std-8         	56034104	        21.12 ns/op	       0 B/op	       0 allocs/op
	// BenchmarkExtractHostname/std-8            	 6690783	       177.8 ns/op	     144 B/op	       1 allocs/op
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
		uftest.URLStrHost,
		uftest.URLStrHostOther,
		uftest.URLStrHostSub,
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
		_ = ufnet.ExtractHostname(input)
	})
}

// longLabel is a long hostname label for testing purposes.  It is 63 characters
// long.
const longLabel = "123456789012345678901234567890123456789012345678901234567890123"

// domainNameTestCases contains test cases for [ufnet.IsDomainName], used for testing,
// fuzzing, and benchmarking.
var domainNameTestCases = []struct {
	want assert.BoolAssertionFunc
	in   string
	name string
}{{
	want: assert.True,
	in:   "dcc",
	name: "no_dot",
}, {
	want: assert.True,
	in:   "1.cc",
	name: "valid_digit",
}, {
	want: assert.True,
	in:   "1.2.cc",
	name: "valid_subdomain_digit",
}, {
	want: assert.True,
	in:   "a.b.cc",
	name: "valid_subdomain_short",
}, {
	want: assert.True,
	in:   "abc.abc.abc",
	name: "valid_subdomain",
}, {
	want: assert.True,
	in:   "a-bc.ab--c.abc",
	name: "valid_subdomain_hyphen",
}, {
	want: assert.True,
	in:   "abc.xn--p1ai",
	name: "valid_xn",
}, {
	want: assert.True,
	in:   "xn--p1ai.xn--p1ai",
	name: "valid_xn_subdomain",
}, {
	want: assert.True,
	in:   "cc",
	name: "valid_tld",
}, {
	want: assert.True,
	in:   longLabel + ".cc",
	name: "valid_long_label",
}, {
	want: assert.True,
	in:   "xn--p1ai",
	name: "valid_tld_xn",
}, {
	want: assert.False,
	in:   "#cc",
	name: "invalid_hash",
}, {
	want: assert.False,
	in:   "a.cc#",
	name: "invalid_hash_end",
}, {
	want: assert.False,
	in:   "abc.xn--",
	name: "invalid_xn",
}, {
	want: assert.False,
	in:   "abc.xn--asd",
	name: "invalid_xn_long",
}, {
	want: assert.False,
	in:   ".a.cc",
	name: "invalid_dot_start",
}, {
	want: assert.False,
	in:   "a.cc.",
	name: "invalid_dot_end",
}, {
	want: assert.False,
	in:   "-a.cc",
	name: "invalid_hyphen_start",
}, {
	want: assert.False,
	in:   "a-.cc",
	name: "invalid_hyphen",
}, {
	want: assert.False,
	in:   "a.1cc",
	name: "invalid_tld_digit_start",
}, {
	want: assert.False,
	in:   "a.cc1",
	name: "invalid_tld_digit_end",
}, {
	want: assert.False,
	in:   "a.c",
	name: "invalid_tld_short",
}, {
	want: assert.False,
	in:   longLabel + "4.cc",
	name: "invalid_long_label",
}}

func TestIsDomainName(t *testing.T) {
	t.Parallel()

	for _, tc := range domainNameTestCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.want(t, ufnet.IsDomainName(tc.in))
		})
	}
}

func FuzzIsDomainName(f *testing.F) {
	f.Skip("Skip because current implementation is performance oriented")

	for _, tc := range domainNameTestCases {
		f.Add(tc.in)
	}

	f.Fuzz(func(t *testing.T, input string) {
		got := ufnet.IsDomainName(input)
		want := netutil.IsValidHostname(input)

		require.Equalf(t, want, got, "input: %q", input)
	})
}

func BenchmarkIsDomainName(b *testing.B) {
	for _, tc := range domainNameTestCases {
		b.Run(tc.name, func(b *testing.B) {
			var ok bool

			b.ReportAllocs()
			for b.Loop() {
				ok = ufnet.IsDomainName(tc.in)
			}

			tc.want(b, ok)
		})
	}

	// Most recent results:
	//
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/urlfilter/internal/ufnet
	//	cpu: Apple M1 Pro
	//	BenchmarkIsDomainName/no_dot-8         	121407466	         9.842 ns/op       0 B/op	       0 allocs/op
	//	BenchmarkIsDomainName/valid_digit-8    	65260395	        18.24 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkIsDomainName/valid_subdomain_digit-8         	48524222	        24.92 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkIsDomainName/valid_subdomain_short-8         	49158753	        25.90 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkIsDomainName/valid_subdomain-8               	44281735	        27.68 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkIsDomainName/valid_subdomain_hyphen-8        	38160909	        31.93 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkIsDomainName/valid_xn-8                      	46931372	        25.56 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkIsDomainName/valid_xn_subdomain-8            	40568235	        29.63 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkIsDomainName/valid_tld-8                     	125186061	         9.547 ns/op       0 B/op	       0 allocs/op
	//	BenchmarkIsDomainName/valid_long_label-8              	19667925	        60.89 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkIsDomainName/valid_tld_xn-8                  	78613132	        15.06 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkIsDomainName/invalid_hash-8                  	140548479	         8.527 ns/op       0 B/op	       0 allocs/op
	//	BenchmarkIsDomainName/invalid_hash_end-8              	62452834	        18.95 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkIsDomainName/invalid_xn-8                    	71505004	        16.66 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkIsDomainName/invalid_xn_long-8               	66671295	        17.31 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkIsDomainName/invalid_dot_start-8             	224679463	         5.338 ns/op       0 B/op	       0 allocs/op
	//	BenchmarkIsDomainName/invalid_dot_end-8               	53001288	        22.80 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkIsDomainName/invalid_hyphen_start-8          	166026781	         7.224 ns/op       0 B/op	       0 allocs/op
	//	BenchmarkIsDomainName/invalid_hyphen-8                	166105177	         7.227 ns/op       0 B/op	       0 allocs/op
	//	BenchmarkIsDomainName/invalid_tld_digit_start-8       	63589354	        19.21 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkIsDomainName/invalid_tld_digit_end-8         	63253327	        19.16 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkIsDomainName/invalid_tld_short-8             	72480548	        16.49 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkIsDomainName/invalid_long_label-8            	181953475	         6.590 ns/op       0 B/op	       0 allocs/op
}
