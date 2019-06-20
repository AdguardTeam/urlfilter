package urlfilter

import "strings"

// RuleList represents a set of filtering rules
type RuleList interface {
	GetID() int                             // GetID returns the rule list identifier
	NewScanner() *RuleScanner               // Creates a new scanner that reads the list contents
	RetrieveRule(ruleIdx int) (Rule, error) // Retrieves a rule by its index
}

// StringRuleList represents a string-based rule list
type StringRuleList struct {
	ID int // Rule list ID

	rulesText      string // String with filtering rules (one per line)
	ignoreCosmetic bool   // Whether to ignore cosmetic rules or not
}

// GetID returns the rule list identifier
func (l *StringRuleList) GetID() int {
	return l.ID
}

// NewScanner creates a new rules scanner that reads the list contents
func (l *StringRuleList) NewScanner() *RuleScanner {
	r := strings.NewReader(l.rulesText)

	return NewRuleScanner(r, l.ID, l.ignoreCosmetic)
}

// RetrieveRule finds and deserializes rule by its index.
// If there's no rule by that index or rule is invalid, it will return an error.
func (l *StringRuleList) RetrieveRule(ruleIdx int) (Rule, error) {

	if ruleIdx < 0 || ruleIdx >= len(l.rulesText) {
		return nil, ErrRuleRetrieval
	}

	endOfLine := strings.IndexByte(l.rulesText[ruleIdx:], '\n')
	if endOfLine == -1 {
		endOfLine = len(l.rulesText)
	} else {
		endOfLine += ruleIdx
	}

	line := strings.TrimSpace(l.rulesText[ruleIdx:endOfLine])
	if len(line) == 0 {
		return nil, ErrRuleRetrieval
	}

	return NewRule(line, l.ID)
}

// TODO: Implement file-based rule list
