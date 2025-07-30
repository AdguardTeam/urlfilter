package filterutil

import (
	"math/rand"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsProbablyIP(t *testing.T) {
	testCases := []struct {
		want assert.BoolAssertionFunc
		name string
		in   string
	}{{
		want: assert.True,
		name: "ipv4",
		in:   "127.0.0.1",
	}, {
		want: assert.False,
		name: "not_ip",
		in:   "random_string",
	}, {
		want: assert.True,
		name: "ipv6",
		in:   "2001:0db8:0000:0000:0000:8a2e:0370:7334",
	}, {
		want: assert.True,
		name: "ipv6_with_brackets",
		in:   "[2001:db8::8a2e:370:7334]",
	}, {
		want: assert.True,
		name: "probably_ip",
		in:   ".:0123456789ABCDEFabcdef[]",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.want(t, IsProbablyIP(tc.in))
		})
	}
}

// randIPv6 returns a random IPv6 address.
func randIPv6(tb testing.TB, r *rand.Rand) (addr netip.Addr) {
	var data [net.IPv6len]byte

	n, err := r.Read(data[:])
	require.NoError(tb, err)
	assert.Equal(tb, net.IPv6len, n)

	return netip.AddrFrom16(data)
}

// boolSink is a sink for bool returning values in benchmarks.
var boolSink bool

func BenchmarkIsProbablyIP(b *testing.B) {
	const n = 128

	// Use constant seed to make benchmark results reproducible.
	r := rand.New(rand.NewSource(n))

	addrStrs := make([]string, n)
	for i := 0; i < n; i++ {
		addrStrs[i] = randIPv6(b, r).String()
	}

	b.Run("random", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			boolSink = IsProbablyIP(addrStrs[i%n])
		}
	})

	// Most recent results:
	//
	// goos: darwin
	// goarch: arm64
	// pkg: github.com/AdguardTeam/urlfilter/filterutil
	// cpu: Apple M1 Pro
	// BenchmarkIsProbablyIP/random-8                  19352161                56.97 ns/op            0 B/op          0 allocs/op
}
