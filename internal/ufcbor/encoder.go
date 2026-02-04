package ufcbor

import (
	"encoding/binary"
	"math"
)

// Encoder is a simple, performant CBOR encoder.  It handles byte slices as
// opposed to an [io.Writer] to improve performance by reducing the amount of
// virtual calls and buffer allocations on the client side.
//
// TODO(a.garipov):  Consider turning into functions.
//
// TODO(a.garipov):  Move to golibs/cborutil.
type Encoder struct{}

// NewEncoder returns a new properly initialized Encoder.
func NewEncoder() (e Encoder) {
	return Encoder{}
}

// EncodeArrayStart appends a start of a CBOR array with the length l to orig
// and returns it.
func (e Encoder) EncodeArrayStart(orig []byte, l uint64) (res []byte) {
	res = orig

	var hdr byte
	var buf [8]byte
	var bufLen int
	switch {
	case l <= ValueUintTinyMax:
		// #nosec G115 -- l has been validated in the case condition.
		hdr = byte(HeaderArrayTinyMin | l)
	case l <= math.MaxUint8:
		hdr = HeaderArray8
		buf[0] = byte(l)
		bufLen = 1
	case l <= math.MaxUint16:
		hdr = HeaderArray16
		binary.BigEndian.PutUint16(buf[:], uint16(l))
		bufLen = 2
	case l <= math.MaxUint32:
		hdr = HeaderArray32
		binary.BigEndian.PutUint32(buf[:], uint32(l))
		bufLen = 4
	default:
		hdr = HeaderArray64
		binary.BigEndian.PutUint64(buf[:], uint64(l))
		bufLen = 8
	}

	res = append(res, hdr)
	res = append(res, buf[:bufLen]...)

	return res
}

// EncodeBytes appends b as a CBOR byte string to orig and returns it.
func (e Encoder) EncodeBytes(orig, b []byte) (res []byte) {
	res = orig

	l := uint64(len(b))

	var hdr byte
	var buf [8]byte
	var bufLen int
	switch {
	case l <= ValueUintTinyMax:
		// #nosec G115 -- l has been validated in the case condition.
		hdr = byte(HeaderBytesTinyMin | l)
	case l <= math.MaxUint8:
		hdr = HeaderBytes8
		buf[0] = byte(l)
		bufLen = 1
	case l <= math.MaxUint16:
		hdr = HeaderBytes16
		binary.BigEndian.PutUint16(buf[:], uint16(l))
		bufLen = 2
	case l <= math.MaxUint32:
		hdr = HeaderBytes32
		binary.BigEndian.PutUint32(buf[:], uint32(l))
		bufLen = 4
	default:
		hdr = HeaderBytes64
		binary.BigEndian.PutUint64(buf[:], uint64(l))
		bufLen = 8
	}

	res = append(res, hdr)
	res = append(res, buf[:bufLen]...)
	res = append(res, b...)

	return res
}

// EncodeInt64 appends n as a CBOR signed integer to orig and returns it.
func (e Encoder) EncodeInt64(orig []byte, n int64) (res []byte) {
	res = orig

	if n >= 0 {
		return e.EncodeUint64(orig, uint64(n))
	}

	var hdr byte
	var buf [8]byte
	var bufLen int
	switch {
	case n >= ValueIntTinyMin:
		// #nosec G115 -- n has been validated in the case condition.
		hdr = byte(HeaderIntTinyMin | -n - 1)
	case n >= -math.MaxUint8:
		hdr = HeaderInt8
		buf[0] = byte(-n - 1)
		bufLen = 1
	case n >= -math.MaxUint16:
		hdr = HeaderInt16
		// #nosec G115 -- n has been validated in the case condition.
		binary.BigEndian.PutUint16(buf[:], uint16(-n-1))
		bufLen = 2
	case n >= -math.MaxUint32:
		hdr = HeaderInt32
		// #nosec G115 -- n has been validated in the case condition.
		binary.BigEndian.PutUint32(buf[:], uint32(-n-1))
		bufLen = 4
	default:
		hdr = HeaderInt64
		// #nosec G115 -- n has been validated in the case condition.
		binary.BigEndian.PutUint64(buf[:], uint64(-n-1))
		bufLen = 8
	}

	res = append(res, hdr)
	res = append(res, buf[:bufLen]...)

	return res
}

// EncodeMapStart appends a start of a CBOR map with the length l to orig and
// returns it.
func (e Encoder) EncodeMapStart(orig []byte, l uint64) (res []byte) {
	res = orig

	var hdr byte
	var buf [8]byte
	var bufLen int
	switch {
	case l <= ValueUintTinyMax:
		// #nosec G115 -- l has been validated in the case condition.
		hdr = byte(HeaderMapTinyMin | l)
	case l <= math.MaxUint8:
		hdr = HeaderMap8
		buf[0] = byte(l)
		bufLen = 1
	case l <= math.MaxUint16:
		hdr = HeaderMap16
		binary.BigEndian.PutUint16(buf[:], uint16(l))
		bufLen = 2
	case l <= math.MaxUint32:
		hdr = HeaderMap32
		binary.BigEndian.PutUint32(buf[:], uint32(l))
		bufLen = 4
	default:
		hdr = HeaderMap64
		binary.BigEndian.PutUint64(buf[:], uint64(l))
		bufLen = 8
	}

	res = append(res, hdr)
	res = append(res, buf[:bufLen]...)

	return res
}

// EncodeUint64 appends u as a CBOR unsigned integer to orig and returns it.
func (e Encoder) EncodeUint64(orig []byte, u uint64) (res []byte) {
	res = orig

	var hdr byte
	var buf [8]byte
	var bufLen int
	switch {
	case u <= ValueUintTinyMax:
		hdr = byte(u)
	case u <= math.MaxUint8:
		hdr = HeaderUint8
		buf[0] = byte(u)
		bufLen = 1
	case u <= math.MaxUint16:
		hdr = HeaderUint16
		binary.BigEndian.PutUint16(buf[:], uint16(u))
		bufLen = 2
	case u <= math.MaxUint32:
		hdr = HeaderUint32
		binary.BigEndian.PutUint32(buf[:], uint32(u))
		bufLen = 4
	default:
		hdr = HeaderUint64
		binary.BigEndian.PutUint64(buf[:], uint64(u))
		bufLen = 8
	}

	res = append(res, hdr)
	res = append(res, buf[:bufLen]...)

	return res
}
