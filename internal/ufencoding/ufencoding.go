// Package ufencoding contains encoding-related utilities.
package ufencoding

// BinaryUnmarshalerRest is the interface for entities that can unmarshal a
// binary representation of itself while also making it easier to track
// consumption of the buffer.
type BinaryUnmarshalerRest interface {
	// UnmarshalBinaryRest decodes the entity from b and returns the rest of it.
	// If err is not nil, rest must be equal to b.
	UnmarshalBinaryRest(b []byte) (rest []byte, err error)
}
