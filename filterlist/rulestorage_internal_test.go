package filterlist

// DisableCache is only used in tests to compare the performance of cached vs.
// uncached lookups.
func (s *RuleStorage) DisableCache() {
	s.cache = nil
}
