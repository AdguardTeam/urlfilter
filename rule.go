package urlfilter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// RuleSyntaxError represents an error while parsing a filtering rule
type RuleSyntaxError struct {
	msg      string
	ruleText string
}

func (e *RuleSyntaxError) Error() string {
	return fmt.Sprintf("syntax error: %s, rule: %s", e.msg, e.ruleText)
}

var (
	// ErrUnsupportedRule signals that this might be a valid rule type,
	// but it is not yet supported by this library
	ErrUnsupportedRule = errors.New("this type of rules is unsupported")

	// ErrRuleRetrieval signals that the rule cannot be retrieved by RuleList
	// by the the specified index
	ErrRuleRetrieval = errors.New("cannot retrieve the rule")
)

// Rule is a base interface for all filtering rules
type Rule interface {
	// Text returns the original rule text
	Text() string

	// GetFilterListID returns ID of the filter list this rule belongs to
	GetFilterListID() int
}

// NewRule creates a new filtering rule from the specified line
// It returns nil if the line is empty or if it is a comment
func NewRule(line string, filterListID int) (Rule, error) {
	line = strings.TrimSpace(line)

	if line == "" || isComment(line) {
		return nil, nil
	}

	if isCosmetic(line) {
		return NewCosmeticRule(line, filterListID)
	}

	f, err := NewHostRule(line, filterListID)
	if err == nil {
		return f, nil
	}

	return NewNetworkRule(line, filterListID)
}

// SerializeRule writes the specified rule to the writer and returns length of the serialized object
// TODO: Deprecated
func SerializeRule(rule Rule, w io.Writer) (int, error) {
	if rule == nil || rule.Text() == "" {
		return 0, errors.New("trying to serialize an invalid rule")
	}

	bytesWritten := 0

	// First byte: rule type ID
	var ruleType byte
	switch rule.(type) {
	case *HostRule:
		ruleType = 1
	case *NetworkRule:
		ruleType = 2
	default:
		return 0, fmt.Errorf("serialization is not supported by this rule type: %s", rule.Text())
	}
	count, err := w.Write([]byte{ruleType})
	bytesWritten += count
	if err != nil {
		return bytesWritten, err
	}

	// Four more bytes: filter list ID
	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, uint32(rule.GetFilterListID()))
	count, err = w.Write(bs)
	bytesWritten += count
	if err != nil {
		return bytesWritten, err
	}

	// Four next bytes: length of the rule text
	ruleText := rule.Text()
	bytes := []byte(ruleText)
	bs = make([]byte, 4)
	binary.BigEndian.PutUint32(bs, uint32(len(bytes)))
	count, err = w.Write(bs)
	bytesWritten += count
	if err != nil {
		return bytesWritten, err
	}

	count, err = w.Write(bytes)
	bytesWritten += count
	if err != nil {
		return bytesWritten, err
	}

	return bytesWritten, nil
}

// DeserializeRule deserializes rule from its binary representation
// Binary representation must have been created by SerializeRule
// TODO: Deprecated
func DeserializeRule(r io.Reader) (Rule, error) {
	var ruleType byte
	var filterListID int
	var ruleText string

	// Read rule type
	bs := make([]byte, 1)
	_, err := r.Read(bs)
	if err != nil {
		return nil, err
	}
	ruleType = bs[0]

	// Read filter list ID
	bs = make([]byte, 4)
	_, err = r.Read(bs)
	if err != nil {
		return nil, err
	}
	filterListID = int(int32(binary.BigEndian.Uint32(bs)))

	// Read rule text length
	_, err = r.Read(bs)
	if err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(bs))
	if length <= 0 {
		return nil, fmt.Errorf("wrong rule text length: %d", length)
	}

	// Read rule text
	bs = make([]byte, length)
	_, err = r.Read(bs)
	if err != nil {
		return nil, err
	}
	ruleText = string(bs)

	// Create rule
	switch ruleType {
	case 1:
		return NewHostRule(ruleText, filterListID)
	case 2:
		return NewNetworkRule(ruleText, filterListID)
	}

	return nil, fmt.Errorf("unsupported rule type: %d", ruleType)
}

// isComment checks if the line is a comment
func isComment(line string) bool {
	if len(line) == 0 {
		return false
	}

	if line[0] == '!' {
		return true
	}

	if line[0] == '#' {
		if len(line) == 1 {
			return true
		}

		// Now we should check that this is not a cosmetic rule
		for _, marker := range cosmeticRulesMarkers {
			if startsAtIndexWith(line, 0, marker) {
				return false
			}
		}

		return true
	}

	return false
}

// loadDomains loads $domain modifier or cosmetic rules domains
// domains is the list of domains
// sep is the separator character. for network rules it is '|', for cosmetic it is ','.
func loadDomains(domains string, sep string) (permittedDomains []string, restrictedDomains []string, err error) {
	if domains == "" {
		err = errors.New("no domains specified")
		return
	}

	list := strings.Split(domains, sep)
	for i := 0; i < len(list); i++ {
		d := list[i]
		restricted := false
		if strings.HasPrefix(d, "~") {
			restricted = true
			d = d[1:]
		}

		if strings.TrimSpace(d) == "" {
			err = fmt.Errorf("empty domain specified: %s", domains)
			return
		}

		if restricted {
			restrictedDomains = append(restrictedDomains, d)
		} else {
			permittedDomains = append(permittedDomains, d)
		}
	}

	return
}
