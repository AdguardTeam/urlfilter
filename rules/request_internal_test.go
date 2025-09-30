package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// effectiveTLDPlusOneTestCases is a list of test cases for the
// effectiveTLDPlusOne function.
var effectiveTLDPlusOneTestCases = []struct {
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

func TestEffectiveTLDPlusOne(t *testing.T) {
	t.Parallel()

	for _, tc := range effectiveTLDPlusOneTestCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, effectiveTLDPlusOne(tc.hostname))
		})
	}
}

func BenchmarkEffectiveTLDPlusOne(b *testing.B) {
	for _, tc := range effectiveTLDPlusOneTestCases {
		b.Run(tc.name, func(b *testing.B) {
			var domain string

			b.ReportAllocs()
			for b.Loop() {
				domain = effectiveTLDPlusOne(tc.hostname)
			}

			assert.Equal(b, tc.want, domain)
		})
	}

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/urlfilter/rules
	//	cpu: Apple M1 Pro
	//	BenchmarkEffectiveTLDPlusOne/simple_domain-8         	10390400	       100.1 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkEffectiveTLDPlusOne/simple_subdomain-8      	11976889	        98.73 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkEffectiveTLDPlusOne/invalid_domain-8        	582381738	         2.056 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkEffectiveTLDPlusOne/invalid_domain_prefix-8 	581595175	         2.062 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkEffectiveTLDPlusOne/invalid_domain_suffix-8 	581499590	         2.050 ns/op	       0 B/op	       0 allocs/op
}
