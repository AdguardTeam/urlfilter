package ufcbor

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/validate"
)

// Decoder is a simple, performant CBOR decoder.  All methods save the first
// error they encounter, and the error should be checked by calling
// [Decoder.Err].  Decoder operates with byte slices as opposed to an
// [io.Reader] to improve performance by reducing the amount of virtual calls
// and buffer allocations on the client side.
type Decoder struct {
	err error
}

// NewDecoder returns a new properly initialized decoder.  d is a value and not
// a pointer to spare allocations.
func NewDecoder() (d Decoder) {
	return Decoder{}
}

// AppendBytes decodes a CBOR byte string from b, appends it to orig and returns
// it.  rest is the rest of b after consuming the byte string.  If there are
// errors, res is orig and rest is b.
func (d *Decoder) AppendBytes(orig, b []byte) (res, rest []byte) {
	var l uint64

	res = orig
	rest = b

	if d.err != nil {
		return res, b
	}

	if len(rest) == 0 {
		d.err = errors.Error("expected byte string header; got empty")

		return res, b
	}

	hdr := rest[0]
	rest = rest[1:]
	switch {
	case hdr >= HeaderBytesTinyMin && hdr <= HeaderBytesTinyMax:
		l = uint64(hdr & TinyMask)
	case hdr == HeaderBytes8:
		l, rest = d.decodeUint64(rest, 1)
	case hdr == HeaderBytes16:
		l, rest = d.decodeUint64(rest, 2)
	case hdr == HeaderBytes32:
		l, rest = d.decodeUint64(rest, 4)
	case hdr == HeaderBytes64:
		l, rest = d.decodeUint64(rest, 8)
	default:
		d.err = fmt.Errorf("expected byte string header; got: %x", hdr)
	}

	return d.appendBytes(res, rest, b, l)
}

// decodeUint64 decodes a CBOR unsigned integer, if b contains it.  rest is the
// rest of b after consuming the unsigned integer.  want must be one of: 1, 2,
// 4, or 8.  If there are errors, l is 0 and rest is b.
func (d *Decoder) decodeUint64(b []byte, want int) (l uint64, rest []byte) {
	rest = b
	err := validate.NoLessThan("length of uint bytes", len(rest), want)
	if err != nil {
		d.err = err

		return 0, b
	}

	switch want {
	case 1:
		l = uint64(rest[0])
	case 2:
		l = uint64(binary.BigEndian.Uint16(rest))
	case 4:
		l = uint64(binary.BigEndian.Uint32(rest))
	case 8:
		l = uint64(binary.BigEndian.Uint64(rest))
	default:
		panic(fmt.Errorf("want: %w: %d", errors.ErrBadEnumValue, want))
	}

	rest = rest[want:]

	return l, rest
}

// appendBytes appends byte string b to orig if b has at least l bytes.  rest is
// the rest of b after consuming the byte string.  If there are errors, res is
// orig and rest is origB.
func (d *Decoder) appendBytes(orig, b, origB []byte, l uint64) (res, rest []byte) {
	if d.err != nil {
		return orig, origB
	}

	res = orig
	rest = b

	if got := uint64(len(rest)); got < l {
		d.err = fmt.Errorf("expected byte string of length %d; got length %d", l, got)

		return orig, origB
	}

	res = append(res, rest[:l]...)
	rest = rest[l:]

	return res, rest
}

// DecodeArrayStart decodes a start of a CBOR array with the length l, if b
// contains it.  rest is the rest of b after consuming the array start.
// If there are errors, l is 0 and rest is b.
func (d *Decoder) DecodeArrayStart(b []byte) (l uint64, rest []byte) {
	rest = b

	if d.err != nil {
		return 0, b
	}

	if len(rest) == 0 {
		d.err = errors.Error("expected array start header; got empty")

		return 0, b
	}

	hdr := rest[0]
	rest = rest[1:]
	if hdr >= HeaderArrayTinyMin && hdr <= HeaderArrayTinyMax {
		return uint64(hdr & TinyMask), rest
	}

	switch hdr {
	case HeaderArray8:
		l, rest = d.decodeUint64(rest, 1)
	case HeaderArray16:
		l, rest = d.decodeUint64(rest, 2)
	case HeaderArray32:
		l, rest = d.decodeUint64(rest, 4)
	case HeaderArray64:
		l, rest = d.decodeUint64(rest, 8)
	default:
		d.err = fmt.Errorf("expected array start header; got: %x", hdr)
	}

	if d.err != nil {
		return 0, b
	}

	return l, rest
}

// DecodeInt64 decodes a CBOR signed integer, if b contains it.  rest is the
// rest of b after consuming the integer.  If there are errors, n is 0 and rest
// is b.
func (d *Decoder) DecodeInt64(b []byte) (n int64, rest []byte) {
	rest = b

	if d.err != nil {
		return 0, b
	}

	if len(rest) == 0 {
		d.err = errors.Error("expected int; got empty")

		return 0, b
	}

	hdr := rest[0]
	if hdr <= HeaderUint64 {
		return d.decodeNonNegativeInt(rest, b)
	}

	return d.decodeNegativeInt(rest, b)
}

// decodeNonNegativeInt decodes a non-negative signed integer.  If there are
// errors, n is 0 and rest is origB.
func (d *Decoder) decodeNonNegativeInt(b, origB []byte) (n int64, rest []byte) {
	rest = b

	u, rest := d.DecodeUint64(rest)
	if u > math.MaxInt64 {
		d.err = fmt.Errorf("expected int; got overflow: %d", u)

		return 0, origB
	}

	return int64(u), rest
}

// decodeNegativeInt decodes a negative signed integer.  If there are errors,
// n is 0 and rest is origB.
func (d *Decoder) decodeNegativeInt(b, origB []byte) (n int64, rest []byte) {
	hdr := b[0]
	rest = b[1:]

	var u uint64
	switch {
	case hdr >= HeaderIntTinyMin && hdr <= HeaderIntTinyMax:
		u = uint64(hdr & TinyMask)
	case hdr == HeaderInt8:
		u, rest = d.decodeUint64(rest, 1)
	case hdr == HeaderInt16:
		u, rest = d.decodeUint64(rest, 2)
	case hdr == HeaderInt32:
		u, rest = d.decodeUint64(rest, 4)
	case hdr == HeaderInt64:
		u, rest = d.decodeUint64(rest, 8)
	default:
		d.err = fmt.Errorf("expected int; got: %x", hdr)
	}

	if d.err != nil {
		return 0, origB
	}

	if u > math.MaxInt64 {
		d.err = fmt.Errorf("expected int; got overflow: %d", u)

		return 0, origB
	}

	n = -int64(u) - 1

	return n, rest
}

// DecodeMapStart decodes a start of a CBOR map with the length l, if b contains
// it.  rest is the rest of b after consuming the array start.  If there are
// errors, l is 0 and rest is b.
func (d *Decoder) DecodeMapStart(b []byte) (l uint64, rest []byte) {
	rest = b

	if d.err != nil {
		return 0, b
	}

	if len(rest) == 0 {
		d.err = errors.Error("expected map start header; got empty")

		return 0, b
	}

	hdr := rest[0]
	rest = rest[1:]
	if hdr >= HeaderMapTinyMin && hdr <= HeaderMapTinyMax {
		l := hdr & TinyMask

		return uint64(l), rest
	}

	switch hdr {
	case HeaderMap8:
		l, rest = d.decodeUint64(rest, 1)
	case HeaderMap16:
		l, rest = d.decodeUint64(rest, 2)
	case HeaderMap32:
		l, rest = d.decodeUint64(rest, 4)
	case HeaderMap64:
		l, rest = d.decodeUint64(rest, 8)
	default:
		d.err = fmt.Errorf("expected map start header; got: %x", hdr)
	}

	if d.err != nil {
		return 0, b
	}

	return l, rest
}

// DecodeUint64 decodes a CBOR unsigned integer, if b contains it.  rest is the
// rest of b after consuming the unsigned integer.  If there are errors, u is 0
// and rest is b.
func (d *Decoder) DecodeUint64(b []byte) (u uint64, rest []byte) {
	rest = b

	if d.err != nil {
		return 0, b
	}

	if len(rest) == 0 {
		d.err = errors.Error("expected uint; got empty")

		return 0, b
	}

	hdr := rest[0]
	rest = rest[1:]
	if hdr <= ValueUintTinyMax {
		return uint64(hdr), rest
	}

	switch hdr {
	case HeaderUint8:
		u, rest = d.decodeUint64(rest, 1)
	case HeaderUint16:
		u, rest = d.decodeUint64(rest, 2)
	case HeaderUint32:
		u, rest = d.decodeUint64(rest, 4)
	case HeaderUint64:
		u, rest = d.decodeUint64(rest, 8)
	default:
		d.err = fmt.Errorf("expected uint; got: %x", hdr)
	}

	if d.err != nil {
		return 0, b
	}

	return u, rest
}

// Err returns the first error the decoder has encountered, if any.
func (d *Decoder) Err() (err error) {
	return d.err
}
