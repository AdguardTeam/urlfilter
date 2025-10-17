package ufcbor_test

// Common numbers for tests.
//
// See https://www.rfc-editor.org/rfc/rfc8949.html#name-examples-of-encoded-cbor-da.
const (
	testIntTiny = -1
	testInt8    = -100
	testInt16   = -1000
	testInt32   = -0x1_0000
	testInt64   = -0x1_0000_0000

	testUintTiny = 1
	testUint8    = 25
	testUint16   = 1000
	testUint32   = 1_000_000
	testUint64   = 1_000_000_000_000
)

// Common CBOR representations of values and their parts for tests.
//
// See https://www.rfc-editor.org/rfc/rfc8949.html#name-examples-of-encoded-cbor-da.
var (
	testCBORInt8  = []byte{0x63}
	testCBORInt16 = []byte{0x03, 0xe7}
	testCBORInt32 = []byte{0x00, 0x00, 0xff, 0xff}
	testCBORInt64 = []byte{0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff}

	testCBORUint8  = []byte{0x19}
	testCBORUint16 = []byte{0x03, 0xe8}
	testCBORUint32 = []byte{0x00, 0x0f, 0x42, 0x40}
	testCBORUint64 = []byte{0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00}

	//lint:ignore U1000 TODO(a.garipov):  Use.
	testCBORInvalid = []byte{0xfe}
)
