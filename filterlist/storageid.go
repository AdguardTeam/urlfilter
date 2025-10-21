package filterlist

import (
	"encoding"
	"fmt"

	"github.com/AdguardTeam/golibs/validate"
	"github.com/AdguardTeam/urlfilter/internal/ufcbor"
	"github.com/AdguardTeam/urlfilter/internal/ufencoding"
	"github.com/AdguardTeam/urlfilter/rules"
)

// StorageID is a compound identifier of a single rule.
type StorageID struct {
	listID  rules.ListID
	ruleIdx int64
}

// NewStorageID converts a pair of a [rules.ListID] and rule-list index into a
// StorageID.  ruleIdx must not be negative.
func NewStorageID(listID rules.ListID, ruleIdx int64) (id StorageID) {
	return StorageID{
		listID:  listID,
		ruleIdx: ruleIdx,
	}
}

// type check
var _ encoding.BinaryAppender = StorageID{}

// AppendBinary implements the [encoding.BinaryAppender] interface for
// StorageID.  Backwards compatibility is only guaranteed within one version of
// the module.
func (id StorageID) AppendBinary(orig []byte) (res []byte, err error) {
	res = orig

	enc := ufcbor.NewEncoder()
	res = enc.EncodeArrayStart(res, 2)

	res = enc.EncodeUint64(res, uint64(id.listID))
	res = enc.EncodeInt64(res, id.ruleIdx)

	return res, nil
}

// type check
var _ encoding.BinaryUnmarshaler = (*StorageID)(nil)

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface for
// *StorageID.  b should be data that has been encoded by
// [StorageID.AppendBinary].
func (id *StorageID) UnmarshalBinary(b []byte) (err error) {
	// TODO(a.garipov):  Validate that the rest of the bytes aren't present?
	_, err = id.UnmarshalBinaryRest(b)

	return err
}

// type check
var _ ufencoding.BinaryUnmarshalerRest = (*StorageID)(nil)

// UnmarshalBinaryRest implements the [ufencoding.BinaryUnmarshalerRest]
// interface for *StorageID.  b should be data that has been encoded by
// [StorageID.AppendBinary].
func (id *StorageID) UnmarshalBinaryRest(b []byte) (rest []byte, err error) {
	rest = b

	dec := ufcbor.NewDecoder()
	l, rest := dec.DecodeArrayStart(rest)
	err = validate.Equal("cbor array length", l, 2)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return b, err
	}

	listID, rest := dec.DecodeUint64(rest)
	ruleIdx, rest := dec.DecodeInt64(rest)

	err = dec.Err()
	if err != nil {
		return b, fmt.Errorf("decoding id values: %w", err)
	}

	id.listID = rules.ListID(listID)
	id.ruleIdx = ruleIdx

	return rest, nil
}
