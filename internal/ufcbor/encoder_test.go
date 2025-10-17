package ufcbor_test

import (
	"bytes"
	"math"
	"testing"

	"github.com/AdguardTeam/urlfilter/internal/ufcbor"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncoder_EncodeArrayStart(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		want []byte
		in   uint64
	}{{
		name: "zero",
		want: []byte{ufcbor.HeaderArrayTinyMin},
		in:   0,
	}, {
		name: "tiny",
		want: []byte{ufcbor.HeaderArrayTinyMin | 1},
		in:   testUintTiny,
	}, {
		name: "byte",
		want: append([]byte{ufcbor.HeaderArray8}, testCBORUint8...),
		in:   testUint8,
	}, {
		name: "short",
		want: append([]byte{ufcbor.HeaderArray16}, testCBORUint16...),
		in:   testUint16,
	}, {
		name: "long",
		want: append([]byte{ufcbor.HeaderArray32}, testCBORUint32...),
		in:   testUint32,
	}, {
		name: "long_long",
		want: append([]byte{ufcbor.HeaderArray64}, testCBORUint64...),
		in:   testUint64,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc := ufcbor.NewEncoder()
			got := enc.EncodeArrayStart(nil, tc.in)
			assert.Equal(t, tc.want, got)
		})
	}

	require.True(t, t.Run("valid_cbor", func(t *testing.T) {
		t.Parallel()

		enc := ufcbor.NewEncoder()

		want := []any{uint64(1), uint64(2), uint64(3)}
		b := enc.EncodeArrayStart(nil, uint64(len(want)))

		for _, n := range want {
			b = enc.EncodeUint64(b, n.(uint64))
		}

		var got any
		err := cbor.Unmarshal(b, &got)
		require.NoError(t, err)

		assert.Equal(t, want, got)
	}))
}

func TestEncoder_EncodeBytes(t *testing.T) {
	t.Parallel()

	// TODO(a.garipov):  Find a way to test larger sizes.

	const (
		len8  = ufcbor.ValueUintTinyMax + 1
		len16 = math.MaxUint8 + 1
		len32 = math.MaxUint16 + 1
	)

	bytes8 := make([]byte, len8)
	for i := range len(bytes8) {
		bytes8[i] = byte(i + 1)
	}

	bytes16 := make([]byte, len16)
	for i := range len(bytes16) {
		bytes16[i] = byte(i + 1)
	}

	bytes32 := make([]byte, len32)
	for i := range len(bytes32) {
		bytes32[i] = byte(i + 1)
	}

	testCases := []struct {
		name string
		in   []byte
		want []byte
	}{{
		name: "zero",
		in:   nil,
		want: []byte{ufcbor.HeaderBytesTinyMin},
	}, {
		name: "tiny",
		in:   []byte{0x00},
		want: []byte{ufcbor.HeaderBytesTinyMin | 1, 0x00},
	}, {
		name: "byte",
		in:   bytes8,
		want: append([]byte{ufcbor.HeaderBytes8, len8}, bytes8...),
	}, {
		name: "short",
		in:   bytes16,
		want: append([]byte{ufcbor.HeaderBytes16, 0x01, 0x00}, bytes16...),
	}, {
		name: "long",
		in:   bytes32,
		want: append([]byte{ufcbor.HeaderBytes32, 0x00, 0x01, 0x00, 0x00}, bytes32...),
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc := ufcbor.NewEncoder()
			got := enc.EncodeBytes(nil, tc.in)
			assert.Equal(t, tc.want, got)
		})
	}

	require.True(t, t.Run("valid_cbor", func(t *testing.T) {
		t.Parallel()

		enc := ufcbor.NewEncoder()

		want := []byte{1, 2, 3}
		b := enc.EncodeBytes(nil, want)

		var got any
		err := cbor.Unmarshal(b, &got)
		require.NoError(t, err)

		assert.Equal(t, want, got)
	}))
}

func TestEncoder_EncodeInt64(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		want []byte
		in   int64
	}{{
		name: "zero",
		want: []byte{ufcbor.HeaderUintTinyMin},
		in:   0,
	}, {
		name: "non_negative",
		want: []byte{ufcbor.HeaderUintTinyMin | 1},
		in:   testUintTiny,
	}, {
		name: "tiny",
		want: []byte{ufcbor.HeaderIntTinyMin},
		in:   testIntTiny,
	}, {
		name: "tiny_min",
		want: []byte{ufcbor.HeaderIntTinyMax},
		in:   ufcbor.ValueIntTinyMin,
	}, {
		name: "byte",
		want: append([]byte{ufcbor.HeaderInt8}, testCBORInt8...),
		in:   testInt8,
	}, {
		name: "short",
		want: append([]byte{ufcbor.HeaderInt16}, testCBORInt16...),
		in:   testInt16,
	}, {
		name: "long",
		want: append([]byte{ufcbor.HeaderInt32}, testCBORInt32...),
		in:   testInt32,
	}, {
		name: "long_long",
		want: append([]byte{ufcbor.HeaderInt64}, testCBORInt64...),
		in:   testInt64,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc := ufcbor.NewEncoder()
			got := enc.EncodeInt64(nil, tc.in)
			assert.Equal(t, tc.want, got)
		})
	}

	require.True(t, t.Run("valid_cbor", func(t *testing.T) {
		t.Parallel()

		enc := ufcbor.NewEncoder()

		var want int64 = -123
		b := enc.EncodeInt64(nil, want)

		var got any
		err := cbor.Unmarshal(b, &got)
		require.NoError(t, err)

		assert.Equal(t, want, got)
	}))
}

func TestEncoder_EncodeMapStart(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		want []byte
		in   uint64
	}{{
		name: "zero",
		want: []byte{ufcbor.HeaderMapTinyMin},
		in:   0,
	}, {
		name: "tiny",
		want: []byte{ufcbor.HeaderMapTinyMin | 1},
		in:   testUintTiny,
	}, {
		name: "byte",
		want: append([]byte{ufcbor.HeaderMap8}, testCBORUint8...),
		in:   testUint8,
	}, {
		name: "short",
		want: append([]byte{ufcbor.HeaderMap16}, testCBORUint16...),
		in:   testUint16,
	}, {
		name: "long",
		want: append([]byte{ufcbor.HeaderMap32}, testCBORUint32...),
		in:   testUint32,
	}, {
		name: "long_long",
		want: append([]byte{ufcbor.HeaderMap64}, testCBORUint64...),
		in:   testUint64,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc := ufcbor.NewEncoder()
			got := enc.EncodeMapStart(nil, tc.in)
			assert.Equal(t, tc.want, got)
		})
	}

	require.True(t, t.Run("valid_cbor", func(t *testing.T) {
		t.Parallel()

		enc := ufcbor.NewEncoder()

		keys := []uint64{1, 3}
		want := map[any]any{
			uint64(1): uint64(2),
			uint64(3): uint64(4),
		}
		b := enc.EncodeMapStart(nil, uint64(len(want)))

		for _, k := range keys {
			b = enc.EncodeUint64(b, k)
			b = enc.EncodeUint64(b, want[k].(uint64))
		}

		var got any
		err := cbor.Unmarshal(b, &got)
		require.NoError(t, err)

		assert.Equal(t, want, got)
	}))
}

func TestEncoder_EncodeUint64(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		want []byte
		in   uint64
	}{{
		name: "zero",
		want: []byte{ufcbor.HeaderUintTinyMin},
		in:   0,
	}, {
		name: "tiny",
		want: []byte{ufcbor.HeaderUintTinyMin | 1},
		in:   testUintTiny,
	}, {
		name: "byte",
		want: append([]byte{ufcbor.HeaderUint8}, testCBORUint8...),
		in:   testUint8,
	}, {
		name: "short",
		want: append([]byte{ufcbor.HeaderUint16}, testCBORUint16...),
		in:   testUint16,
	}, {
		name: "long",
		want: append([]byte{ufcbor.HeaderUint32}, testCBORUint32...),
		in:   testUint32,
	}, {
		name: "long_long",
		want: append([]byte{ufcbor.HeaderUint64}, testCBORUint64...),
		in:   testUint64,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc := ufcbor.NewEncoder()
			got := enc.EncodeUint64(nil, tc.in)
			assert.Equal(t, tc.want, got)
		})
	}

	require.True(t, t.Run("valid_cbor", func(t *testing.T) {
		t.Parallel()

		enc := ufcbor.NewEncoder()

		var want uint64 = 123
		b := enc.EncodeUint64(nil, want)

		var got any
		err := cbor.Unmarshal(b, &got)
		require.NoError(t, err)

		assert.Equal(t, want, got)
	}))
}

func BenchmarkEncoder(b *testing.B) {
	require.True(b, b.Run("EncodeArrayStart", func(b *testing.B) {
		enc := ufcbor.NewEncoder()

		// Warmup to fill the slice.
		data := enc.EncodeArrayStart(nil, testUint64)

		b.ReportAllocs()
		for b.Loop() {
			data = enc.EncodeArrayStart(data[:0], testUint64)
		}
	}))

	require.True(b, b.Run("EncodeInt64", func(b *testing.B) {
		enc := ufcbor.NewEncoder()

		// Warmup to fill the slice.
		data := enc.EncodeInt64(nil, testInt64)

		b.ReportAllocs()
		for b.Loop() {
			data = enc.EncodeInt64(data[:0], testInt64)
		}
	}))

	require.True(b, b.Run("EncodeMapStart", func(b *testing.B) {
		enc := ufcbor.NewEncoder()

		// Warmup to fill the slice.
		data := enc.EncodeMapStart(nil, testUint64)

		b.ReportAllocs()
		for b.Loop() {
			data = enc.EncodeMapStart(data[:0], testUint64)
		}
	}))

	require.True(b, b.Run("EncodeUint64", func(b *testing.B) {
		enc := ufcbor.NewEncoder()

		// Warmup to fill the slice.
		data := enc.EncodeUint64(nil, testUint64)

		b.ReportAllocs()
		for b.Loop() {
			data = enc.EncodeUint64(data[:0], testUint64)
		}
	}))

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/urlfilter/internal/ufcbor
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkEncoder/EncodeArrayStart-16         	215035488	         5.491 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkEncoder/EncodeInt64-16              	232748745	         5.016 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkEncoder/EncodeMapStart-16           	242990394	         4.990 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkEncoder/EncodeUint64-16             	234323613	         5.057 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkEncoder_EncodeBytes(b *testing.B) {
	benchCases := []struct {
		name string
		len  int
	}{{
		name: "tiny",
		len:  1,
	}, {
		name: "byte",
		len:  ufcbor.ValueUintTinyMax + 1,
	}, {
		name: "short",
		len:  math.MaxUint8 + 1,
	}, {
		name: "long",
		len:  math.MaxUint16 + 1,
	}}

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			enc := ufcbor.NewEncoder()
			byteString := bytes.Repeat([]byte("a"), bc.len)

			// Warmup to fill the slice.
			data := enc.EncodeBytes(nil, byteString)

			b.ReportAllocs()
			for b.Loop() {
				data = enc.EncodeBytes(data[:0], byteString)
			}
		})
	}

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/urlfilter/internal/ufcbor
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkEncoder_EncodeBytes/tiny-16         	222893108	         5.403 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkEncoder_EncodeBytes/byte-16         	188134428	         6.406 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkEncoder_EncodeBytes/short-16        	100000000	        11.05 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkEncoder_EncodeBytes/long-16         	 1000000	      1057 ns/op	       0 B/op	       0 allocs/op
}
