package filterutil

// FastHashBetween implements the djb2 hash algorithm.
func FastHashBetween(str string, begin, end int) uint32 {
	hash := uint32(5381)
	for i := begin; i < end; i++ {
		hash = (hash * 33) ^ uint32(str[i])
	}
	return hash
}

// FastHash implements the djb2 hash algorithm.
//
// TODO(e.burkov): Inspect all uses.  Perhaps use maphash.
func FastHash(str string) uint32 {
	if str == "" {
		return 0
	}
	return FastHashBetween(str, 0, len(str))
}
