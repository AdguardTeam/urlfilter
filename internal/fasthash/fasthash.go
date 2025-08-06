// Package fasthash contains utilities for fast hashing of strings.
//
// TODO(s.chzhen):  Remove this.
package fasthash

// String implements the djb2 hash algorithm for a string.
//
// TODO(e.burkov): Inspect all uses.  Perhaps use maphash.
func String(str string) (hash uint32) {
	if str == "" {
		return 0
	}

	hash = uint32(5381)
	for i := range len(str) {
		hash = (hash * 33) ^ uint32(str[i])
	}

	return hash
}
