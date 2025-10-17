package ufcbor_test

import (
	"bytes"
	"math"
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/urlfilter/internal/ufcbor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecoder_AppendBytes(t *testing.T) {
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
		name       string
		wantErrMsg string
		in         []byte
		want       []byte
	}{{
		name:       "zero",
		wantErrMsg: "",
		in:         []byte{ufcbor.HeaderBytesTinyMin},
		want:       nil,
	}, {
		name:       "tiny",
		wantErrMsg: "",
		in:         []byte{ufcbor.HeaderBytesTinyMin | 1, 0x00},
		want:       []byte{0x00},
	}, {
		name:       "byte",
		wantErrMsg: "",
		in:         append([]byte{ufcbor.HeaderBytes8, len8}, bytes8...),
		want:       bytes8,
	}, {
		name:       "short",
		wantErrMsg: "",
		in:         append([]byte{ufcbor.HeaderBytes16, 0x01, 0x00}, bytes16...),
		want:       bytes16,
	}, {
		name:       "long",
		wantErrMsg: "",
		in:         append([]byte{ufcbor.HeaderBytes32, 0x00, 0x01, 0x00, 0x00}, bytes32...),
		want:       bytes32,
	}, {
		name:       "nil",
		wantErrMsg: "expected byte string header; got empty",
		in:         nil,
		want:       nil,
	}, {
		name:       "invalid",
		wantErrMsg: "expected byte string header; got: fe",
		in:         testCBORInvalid,
		want:       nil,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dec := ufcbor.NewDecoder()
			got, _ := dec.AppendBytes(nil, tc.in)
			assert.Equal(t, tc.want, got)

			err := dec.Err()
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

func TestDecoder_DecodeArrayStart(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		wantErrMsg string
		in         []byte
		want       uint64
	}{{
		name:       "zero",
		wantErrMsg: "",
		in:         []byte{ufcbor.HeaderArrayTinyMin},
		want:       0,
	}, {
		name:       "tiny",
		wantErrMsg: "",
		in:         []byte{ufcbor.HeaderArrayTinyMin | 1},
		want:       testUintTiny,
	}, {
		name:       "byte",
		wantErrMsg: "",
		in:         append([]byte{ufcbor.HeaderArray8}, testCBORUint8...),
		want:       testUint8,
	}, {
		name:       "short",
		wantErrMsg: "",
		in:         append([]byte{ufcbor.HeaderArray16}, testCBORUint16...),
		want:       testUint16,
	}, {
		name:       "long",
		wantErrMsg: "",
		in:         append([]byte{ufcbor.HeaderArray32}, testCBORUint32...),
		want:       testUint32,
	}, {
		name:       "long_long",
		wantErrMsg: "",
		in:         append([]byte{ufcbor.HeaderArray64}, testCBORUint64...),
		want:       testUint64,
	}, {
		name:       "nil",
		wantErrMsg: "expected array start header; got empty",
		in:         nil,
		want:       0,
	}, {
		name:       "invalid",
		wantErrMsg: "expected array start header; got: fe",
		in:         testCBORInvalid,
		want:       0,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dec := ufcbor.NewDecoder()
			got, _ := dec.DecodeArrayStart(tc.in)
			assert.Equal(t, tc.want, got)

			err := dec.Err()
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

func TestDecoder_DecodeInt64(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		wantErrMsg string
		in         []byte
		want       int64
	}{{
		name:       "zero",
		wantErrMsg: "",
		in:         []byte{0x00},
		want:       0,
	}, {
		name:       "positive",
		wantErrMsg: "",
		in:         []byte{0x01},
		want:       testUintTiny,
	}, {
		name:       "tiny",
		wantErrMsg: "",
		in:         []byte{ufcbor.HeaderIntTinyMin},
		want:       testIntTiny,
	}, {
		name:       "byte",
		wantErrMsg: "",
		in:         append([]byte{ufcbor.HeaderInt8}, testCBORInt8...),
		want:       testInt8,
	}, {
		name:       "short",
		wantErrMsg: "",
		in:         append([]byte{ufcbor.HeaderInt16}, testCBORInt16...),
		want:       testInt16,
	}, {
		name:       "long",
		wantErrMsg: "",
		in:         append([]byte{ufcbor.HeaderInt32}, testCBORInt32...),
		want:       testInt32,
	}, {
		name:       "long_long",
		wantErrMsg: "",
		in:         append([]byte{ufcbor.HeaderInt64}, testCBORInt64...),
		want:       testInt64,
	}, {
		name:       "nil",
		wantErrMsg: "expected int; got empty",
		in:         nil,
		want:       0,
	}, {
		name:       "invalid",
		wantErrMsg: "expected int; got: fe",
		in:         testCBORInvalid,
		want:       0,
	}, {
		name:       "overflow",
		wantErrMsg: "expected int; got overflow: 18446744073709551615",
		in:         append([]byte{ufcbor.HeaderInt64}, bytes.Repeat([]byte{0xff}, 8)...),
		want:       0,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dec := ufcbor.NewDecoder()
			got, _ := dec.DecodeInt64(tc.in)
			assert.Equal(t, tc.want, got)

			err := dec.Err()
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

func TestDecoder_DecodeMapStart(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		wantErrMsg string
		in         []byte
		want       uint64
	}{{
		name:       "zero",
		wantErrMsg: "",
		in:         []byte{ufcbor.HeaderMapTinyMin},
		want:       0,
	}, {
		name:       "tiny",
		wantErrMsg: "",
		in:         []byte{ufcbor.HeaderMapTinyMin | 1},
		want:       testUintTiny,
	}, {
		name:       "byte",
		wantErrMsg: "",
		in:         append([]byte{ufcbor.HeaderMap8}, testCBORUint8...),
		want:       testUint8,
	}, {
		name:       "short",
		wantErrMsg: "",
		in:         append([]byte{ufcbor.HeaderMap16}, testCBORUint16...),
		want:       testUint16,
	}, {
		name:       "long",
		wantErrMsg: "",
		in:         append([]byte{ufcbor.HeaderMap32}, testCBORUint32...),
		want:       testUint32,
	}, {
		name:       "long_long",
		wantErrMsg: "",
		in:         append([]byte{ufcbor.HeaderMap64}, testCBORUint64...),
		want:       testUint64,
	}, {
		name:       "nil",
		wantErrMsg: "expected map start header; got empty",
		in:         nil,
		want:       0,
	}, {
		name:       "invalid",
		wantErrMsg: "expected map start header; got: fe",
		in:         testCBORInvalid,
		want:       0,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dec := ufcbor.NewDecoder()
			got, _ := dec.DecodeMapStart(tc.in)
			assert.Equal(t, tc.want, got)

			err := dec.Err()
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

func TestDecoder_DecodeUint64(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		wantErrMsg string
		in         []byte
		want       uint64
	}{{
		name:       "zero",
		wantErrMsg: "",
		in:         []byte{ufcbor.HeaderUintTinyMin},
		want:       0,
	}, {
		name:       "tiny",
		wantErrMsg: "",
		in:         []byte{ufcbor.HeaderUintTinyMin | 1},
		want:       testUintTiny,
	}, {
		name:       "byte",
		wantErrMsg: "",
		in:         append([]byte{ufcbor.HeaderUint8}, testCBORUint8...),
		want:       testUint8,
	}, {
		name:       "short",
		wantErrMsg: "",
		in:         append([]byte{ufcbor.HeaderUint16}, testCBORUint16...),
		want:       testUint16,
	}, {
		name:       "long",
		wantErrMsg: "",
		in:         append([]byte{ufcbor.HeaderUint32}, testCBORUint32...),
		want:       testUint32,
	}, {
		name:       "long_long",
		wantErrMsg: "",
		in:         append([]byte{ufcbor.HeaderUint64}, testCBORUint64...),
		want:       testUint64,
	}, {
		name:       "nil",
		wantErrMsg: "expected uint; got empty",
		in:         nil,
		want:       0,
	}, {
		name:       "invalid",
		wantErrMsg: "expected uint; got: fe",
		in:         testCBORInvalid,
		want:       0,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dec := ufcbor.NewDecoder()
			got, _ := dec.DecodeUint64(tc.in)
			assert.Equal(t, tc.want, got)

			err := dec.Err()
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

func BenchmarkDecoder(b *testing.B) {
	require.True(b, b.Run("DecodeArrayStart", func(b *testing.B) {
		enc := ufcbor.NewEncoder()
		data := enc.EncodeArrayStart(nil, testUint64)

		dec := ufcbor.NewDecoder()
		var got uint64
		b.ReportAllocs()
		for b.Loop() {
			got, _ = dec.DecodeArrayStart(data)
		}

		require.Equal(b, uint64(testUint64), got)
		require.NoError(b, dec.Err())
	}))

	require.True(b, b.Run("DecodeInt64", func(b *testing.B) {
		enc := ufcbor.NewEncoder()
		data := enc.EncodeInt64(nil, testInt64)

		dec := ufcbor.NewDecoder()
		var got int64
		b.ReportAllocs()
		for b.Loop() {
			got, _ = dec.DecodeInt64(data)
		}

		require.Equal(b, int64(testInt64), got)
		require.NoError(b, dec.Err())
	}))

	require.True(b, b.Run("DecodeMapStart", func(b *testing.B) {
		enc := ufcbor.NewEncoder()
		data := enc.EncodeMapStart(nil, testUint64)

		dec := ufcbor.NewDecoder()
		var got uint64
		b.ReportAllocs()
		for b.Loop() {
			got, _ = dec.DecodeMapStart(data)
		}

		require.Equal(b, uint64(testUint64), got)
		require.NoError(b, dec.Err())
	}))

	require.True(b, b.Run("DecodeUint64", func(b *testing.B) {
		enc := ufcbor.NewEncoder()
		data := enc.EncodeUint64(nil, testUint64)

		dec := ufcbor.NewDecoder()
		var got uint64
		b.ReportAllocs()
		for b.Loop() {
			got, _ = dec.DecodeUint64(data)
		}

		require.Equal(b, uint64(testUint64), got)
		require.NoError(b, dec.Err())
	}))

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/urlfilter/internal/ufcbor
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkDecoder/DecodeArrayStart-16         	213454928	         5.615 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkDecoder/DecodeInt64-16              	197380826	         6.115 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkDecoder/DecodeMapStart-16           	213313791	         5.624 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkDecoder/DecodeUint64-16             	214460706	         5.599 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkDecoder_AppendBytes(b *testing.B) {
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

			data := enc.EncodeBytes(nil, byteString)

			// Warmup to fill the slice.
			dec := ufcbor.NewDecoder()
			got, _ := dec.AppendBytes(nil, data)
			require.Equal(b, byteString, got)
			require.NoError(b, dec.Err())

			b.ReportAllocs()
			for b.Loop() {
				got, _ = dec.AppendBytes(got[:0], data)
			}

			require.Equal(b, byteString, got)
			require.NoError(b, dec.Err())
		})
	}

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/urlfilter/internal/ufcbor
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkDecoder_AppendBytes/tiny-16         	202560172	         5.930 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkDecoder_AppendBytes/byte-16         	124581495	         9.598 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkDecoder_AppendBytes/short-16        	97928478	        12.29 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkDecoder_AppendBytes/long-16         	 1000000	      1049 ns/op	       0 B/op	       0 allocs/op
}

func FuzzDecoder(f *testing.F) {
	type seed struct {
		Bytes       []byte
		Int64       int64
		ArrayLength uint64
		MapLength   uint64
		Uint64      uint64
	}

	seeds := []seed{{
		ArrayLength: math.MaxUint64,
	}, {
		MapLength: math.MaxUint64,
	}, {
		Uint64: math.MaxUint64,
	}, {
		Int64: testIntTiny,
	}, {
		Int64: math.MaxInt64,
	}, {
		Int64: math.MinInt64,
	}}

	for _, s := range seeds {
		f.Add(s.Bytes, s.Int64, s.ArrayLength, s.MapLength, s.Uint64)
	}

	f.Fuzz(func(t *testing.T, bytes []byte, i64 int64, arrLen, mapLen, u64 uint64) {
		enc := ufcbor.NewEncoder()
		dec := ufcbor.NewDecoder()

		require.True(t, t.Run("AppendBytes", func(t *testing.T) {
			encoded := enc.EncodeBytes(nil, bytes)
			decoded, _ := dec.AppendBytes(nil, encoded)

			if len(bytes) == 0 {
				assert.Empty(t, decoded)
			} else {
				assert.Equal(t, bytes, decoded)
			}

			assert.NoError(t, dec.Err())
		}))

		require.True(t, t.Run("DecodeArrayStart", func(t *testing.T) {
			encoded := enc.EncodeArrayStart(nil, arrLen)
			decoded, _ := dec.DecodeArrayStart(encoded)

			assert.Equal(t, arrLen, decoded)
			assert.NoError(t, dec.Err())
		}))

		require.True(t, t.Run("DecodeInt64", func(t *testing.T) {
			encoded := enc.EncodeInt64(nil, i64)
			decoded, _ := dec.DecodeInt64(encoded)

			assert.Equal(t, i64, decoded)
			assert.NoError(t, dec.Err())
		}))

		require.True(t, t.Run("DecodeMapStart", func(t *testing.T) {
			encoded := enc.EncodeMapStart(nil, mapLen)
			decoded, _ := dec.DecodeMapStart(encoded)

			assert.Equal(t, mapLen, decoded)
			assert.NoError(t, dec.Err())
		}))

		require.True(t, t.Run("DecodeUint64", func(t *testing.T) {
			encoded := enc.EncodeUint64(nil, u64)
			decoded, _ := dec.DecodeUint64(encoded)

			assert.Equal(t, u64, decoded)
			assert.NoError(t, dec.Err())
		}))
	})
}

func FuzzDecoder_panic(f *testing.F) {
	for _, seed := range [][]byte{
		nil,
		{},
		{0x00},
		{0x01},
		{0xff},
		{0x18, 0x18},
		{0x19, 0x03, 0xe8},
		{0x1a, 0x00, 0x0f, 0x42, 0x40},
		{0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00},
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		dec := ufcbor.NewDecoder()

		require.True(t, t.Run("AppendBytes", func(t *testing.T) {
			assert.NotPanics(t, func() {
				_, _ = dec.AppendBytes(nil, input)
			})
		}))

		require.True(t, t.Run("DecodeArrayStart", func(t *testing.T) {
			assert.NotPanics(t, func() {
				_, _ = dec.DecodeArrayStart(input)
			})
		}))

		require.True(t, t.Run("DecodeInt64", func(t *testing.T) {
			assert.NotPanics(t, func() {
				_, _ = dec.DecodeInt64(input)
			})
		}))

		require.True(t, t.Run("DecodeMapStart", func(t *testing.T) {
			assert.NotPanics(t, func() {
				_, _ = dec.DecodeMapStart(input)
			})
		}))

		require.True(t, t.Run("DecodeUint64", func(t *testing.T) {
			assert.NotPanics(t, func() {
				_, _ = dec.DecodeUint64(input)
			})
		}))
	})
}
