package filterutil

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func BenchmarkParseIP(b *testing.B) {
	b.Run("filterutil.ParseIP", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ParseIP("domain.com")
			ParseIP("invalid:ip")
		}
	})

	b.Run("net.ParseIP", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			net.ParseIP("domain.com")
			net.ParseIP("invalid:ip")
		}
	})
}

func TestParseIP(t *testing.T) {
	testCases := []struct {
		s string
	}{{
		s: "127.0.0.1",
	}, {
		s: "random string",
	}, {
		s: "2001:0db8:0000:0000:0000:8a2e:0370:7334",
	}, {
		s: "[2001:db8::8a2e:370:7334]",
	}}

	for _, tc := range testCases {
		t.Run(tc.s, func(t *testing.T) {
			require.Equal(t, net.ParseIP(tc.s), ParseIP(tc.s))
		})
	}
}
