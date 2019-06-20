package urlfilter

// RuleStorageScanner scans multiple RuleScanner instances
// The rule index is built from the rule index in the list + the list ID
// First 4 bytes is the rule index in the list
// Second 4 bytes is the list ID
type RuleStorageScanner struct {
	// Scanners is the list of list scanners backing this combined scanner
	Scanners []*RuleScanner

	currentScanner    *RuleScanner
	currentScannerIdx int // Index of the current scanner
}

func (s *RuleStorageScanner) Scan() bool {
	if len(s.Scanners) == 0 {
		return false
	}

	if s.currentScanner == nil {
		s.currentScannerIdx = 0
		s.currentScanner = s.Scanners[s.currentScannerIdx]
	}

	for {
		scan := s.currentScanner.Scan()
		if scan {
			return true
		}

		// Take the next scanner or just return false if there's nothing more
		if s.currentScannerIdx == (len(s.Scanners) - 1) {
			return false
		}

		s.currentScannerIdx++
		s.currentScanner = s.Scanners[s.currentScannerIdx]
	}
}

func (s *RuleStorageScanner) Rule() (Rule, int64) {
	if s.currentScanner == nil {
		return nil, 0
	}

	f, idx := s.currentScanner.Rule()
	if f == nil {
		return nil, 0
	}

	return f, ruleListIdxToStorageIdx(f.GetFilterListID(), idx)
}

// ruleListIdxToStorageIdx converts pair of listID and rule list index
// to a single int64 "storage index"
func ruleListIdxToStorageIdx(listID int, ruleIdx int) int64 {
	return int64(listID)<<32 | int64(ruleIdx)&0xFFFFFFFF
}

// storageIdxToRuleListIdx converts the "storage index" to two integers:
// listID -- rule list identifier
// ruleIdx -- index of the rule in the list
func storageIdxToRuleListIdx(storageIdx int64) (listID int, ruleIdx int) {
	listID = int(storageIdx >> 32)
	ruleIdx = int(storageIdx)
	return
}
