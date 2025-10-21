package lookup

import (
	"encoding"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"

	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/internal/ufcbor"
	"github.com/AdguardTeam/urlfilter/internal/ufencoding"
	"github.com/AdguardTeam/urlfilter/rules"
)

// shortcutLength is the fixed length used to form URL "shortcuts".
const shortcutLength = 5

// shortcut is a single shortcut.
type shortcut string

// ShortcutIndex is an index that relies on the rule shortcuts to quickly find
// matching rules:
//
//  1. From the rule, it extracts the longest substring without special
//     characters; this string is the [shortcut].
//  2. It uses a sliding window of [shortcutLength] and puts it into its map.
//  3. When it matches a request, it takes all substrings of length
//     [shortcutsLength] from it and checks if there are any rules in the map.
//
// NOTE: only the rules with a shortcut are eligible for this index.
//
// TODO(a.garipov):  Consider all non-regexp rules as having shortcuts?
type ShortcutIndex struct {
	// shortcutsPool contains slices of shortcuts for reuse.
	shortcutsPool *syncutil.Pool[[]shortcut]

	// shortcuts is the index of a shortcut to its data.
	shortcuts map[shortcut][]filterlist.StorageID
}

// shortcutsInARuleEst is the estimate for the number of shortcuts in a rule
// based on an analysis of the AdGuard DNS filtering-rule list.
const shortcutsInARuleEst = 16

// NewShortcutIndex creates a new instance of *ShortcutIndex.
func NewShortcutIndex() (idx *ShortcutIndex) {
	return &ShortcutIndex{
		shortcutsPool: syncutil.NewSlicePool[shortcut](shortcutsInARuleEst),
		shortcuts:     map[shortcut][]filterlist.StorageID{},
	}
}

// Add adds r to the index if r is eligible.  r must not be nil.
func (idx *ShortcutIndex) Add(r *rules.NetworkRule, id filterlist.StorageID) (ok bool) {
	shortcutsPtr := idx.shortcutsPool.Get()
	defer idx.shortcutsPool.Put(shortcutsPtr)

	*shortcutsPtr = appendRuleShortcuts((*shortcutsPtr)[:0], r)
	if len(*shortcutsPtr) == 0 {
		return false
	}

	var minSC shortcut
	minLen := uint64(math.MaxUint64)
	for _, sc := range *shortcutsPtr {
		scIDs := idx.shortcuts[sc]

		if scIDs == nil {
			minSC = sc
			break
		}

		lenSCIds := uint64(len(scIDs))
		if lenSCIds < minLen {
			minLen = lenSCIds
			minSC = sc
		}
	}

	idx.shortcuts[minSC] = append(idx.shortcuts[minSC], id)

	return true
}

// appendRuleShortcuts appends shortcuts to orig and returns them.  r must not
// be nil.
func appendRuleShortcuts(orig []shortcut, r *rules.NetworkRule) (res []shortcut) {
	res = orig

	if len(r.Shortcut) < shortcutLength {
		return res
	}

	if isAnyURLShortcut(r) {
		return res
	}

	for i := range len(r.Shortcut) - shortcutLength {
		res = append(res, shortcut(r.Shortcut[i:i+shortcutLength]))
	}

	return res
}

// isAnyURLShortcut checks if the rule potentially matches too many URLs.  It is
// better use another type of index for these kinds of rules.
//
// TODO(a.garipov):  Inspect and optimize.
func isAnyURLShortcut(r *rules.NetworkRule) (ok bool) {
	switch scLen := len(r.Shortcut); {
	case
		scLen < len("ws://")+1 && strings.HasPrefix(r.Shortcut, "ws:"),
		scLen < len("wss://")+1 && strings.HasPrefix(r.Shortcut, "wss:"),
		scLen < len("|wss://")+1 && strings.HasPrefix(r.Shortcut, "|ws"),
		scLen < len("https://")+1 && strings.HasPrefix(r.Shortcut, "http"),
		scLen < len("|https://")+1 && strings.HasPrefix(r.Shortcut, "|http"):
		return true
	default:
		return false
	}
}

// type check
var _ encoding.BinaryAppender = (*ShortcutIndex)(nil)

// AppendBinary implements the [encoding.BinaryAppender] interface for
// *ShortcutIndex.  The only guarantee with regards to the backwards
// compatibility is the following: when the result of AppendBinary is fed into
// [ShortcutIndex.UnmarshalBinary] of an empty or reset *ShortcutIndex, the
// results of [ShortcutIndex.AppendMatching] of this new table are the same as
// those of the original one; all of this being within one version of the
// module.
func (idx *ShortcutIndex) AppendBinary(orig []byte) (res []byte, err error) {
	// Pseudo-JSON of the CBOR output:
	//
	//	{
	//	  "domai": [
	//	    [ 1, 0 ],
	//	    [ 1, 1 ],
	//	    // …
	//	  ],
	//	  "omain": [
	//	    [ 1, 1 ],
	//	    [ 1, 2 ],
	//	    // …
	//	  ],
	//	  // …
	//	}
	//

	res = orig

	enc := ufcbor.NewEncoder()

	res = enc.EncodeMapStart(res, uint64(len(idx.shortcuts)))
	for _, sc := range slices.Sorted(maps.Keys(idx.shortcuts)) {
		res = enc.EncodeBytes(res, []byte(sc))

		ids := idx.shortcuts[sc]
		res = enc.EncodeArrayStart(res, uint64(len(ids)))
		for i, id := range ids {
			res, err = id.AppendBinary(res)
			if err != nil {
				return res, fmt.Errorf("shortcut %q: encoding id at index %d: %w", sc, i, err)
			}
		}
	}

	return res, nil
}

// AppendMatching appends the IDs of the rules matching r to orig and returns
// it.  r must not be nil.
func (idx *ShortcutIndex) AppendMatching(
	orig []filterlist.StorageID,
	r *rules.Request,
) (res []filterlist.StorageID) {
	res = orig

	l := len(r.URLLowerCase)
	if l < shortcutLength {
		return res
	}

	for i := range l - shortcutLength {
		sc := shortcut(r.URLLowerCase[i : i+shortcutLength])
		ids := idx.shortcuts[sc]
		if len(ids) == 0 {
			continue
		}

		res = append(res, ids...)
	}

	return res
}

// Reset prepares idx for reuse.
func (idx *ShortcutIndex) Reset() {
	clear(idx.shortcuts)
}

// type check
var _ encoding.BinaryUnmarshaler = (*ShortcutIndex)(nil)

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface for
// *ShortcutIndex.  b should be data that has been encoded by
// [ShortcutIndex.AppendBinary].
func (idx *ShortcutIndex) UnmarshalBinary(b []byte) (err error) {
	_, err = idx.UnmarshalBinaryRest(b)

	return err
}

// type check
var _ ufencoding.BinaryUnmarshalerRest = (*ShortcutIndex)(nil)

// UnmarshalBinaryRest implements the [ufencoding.BinaryUnmarshalerRest]
// interface for *ShortcutIndex.  b should be data that has been encoded by
// [ShortcutIndex.AppendBinary].
func (idx *ShortcutIndex) UnmarshalBinaryRest(b []byte) (rest []byte, err error) {
	rest = b

	dec := ufcbor.NewDecoder()

	l, rest := dec.DecodeMapStart(rest)

	var keyBuffer []byte
	idx.shortcuts = make(map[shortcut][]filterlist.StorageID, l)
	for range l {
		keyBuffer, rest = dec.AppendBytes(keyBuffer[:0], rest)

		var idsLen uint64
		idsLen, rest = dec.DecodeArrayStart(rest)

		ids := make([]filterlist.StorageID, 0, idsLen)
		for i := range idsLen {
			var id filterlist.StorageID
			rest, err = id.UnmarshalBinaryRest(rest)
			if err != nil {
				return b, fmt.Errorf("decoding shortcut %q: id at index %d: %w", keyBuffer, i, err)
			}

			ids = append(ids, id)
		}

		idx.shortcuts[shortcut(keyBuffer)] = ids
	}

	err = dec.Err()
	if err != nil {
		return b, err
	}

	return rest, nil
}
