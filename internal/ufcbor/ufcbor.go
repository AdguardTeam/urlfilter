// Package ufcbor provides utilities for fast and reflect-less [CBOR] decoding
// and encoding.
//
// [CBOR]: https://cbor.io/
package ufcbor

// TinyMask is the bit mask for obtaining tiny values in headers.
const TinyMask = 0b0001_1111

// Header constants.
//
// See https://www.rfc-editor.org/rfc/rfc8949.html#name-jump-table-for-initial-byte.
const (
	HeaderUintTinyMin = 0x00
	HeaderUintTinyMax = 0x17
	HeaderUint8       = 0x18
	HeaderUint16      = 0x19
	HeaderUint32      = 0x1a
	HeaderUint64      = 0x1b

	HeaderIntTinyMin = 0x20
	HeaderIntTinyMax = 0x37
	HeaderInt8       = 0x38
	HeaderInt16      = 0x39
	HeaderInt32      = 0x3a
	HeaderInt64      = 0x3b

	HeaderBytesTinyMin = 0x40
	HeaderBytesTinyMax = 0x57
	HeaderBytes8       = 0x58
	HeaderBytes16      = 0x59
	HeaderBytes32      = 0x5a
	HeaderBytes64      = 0x5b

	HeaderArrayTinyMin = 0x80
	HeaderArrayTinyMax = 0x97
	HeaderArray8       = 0x98
	HeaderArray16      = 0x99
	HeaderArray32      = 0x9a
	HeaderArray64      = 0x9b

	HeaderMapTinyMin = 0xa0
	HeaderMapTinyMax = 0xb7
	HeaderMap8       = 0xb8
	HeaderMap16      = 0xb9
	HeaderMap32      = 0xba
	HeaderMap64      = 0xbb
)

// Value constants.
//
// See https://www.rfc-editor.org/rfc/rfc8949.html#name-jump-table-for-initial-byte.
const (
	ValueIntTinyMin = -0x18
	ValueIntTinyMax = -0x01

	ValueUintTinyMin = 0x00
	ValueUintTinyMax = 0x17
)
