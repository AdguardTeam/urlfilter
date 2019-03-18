package urlfilter

// Engine represents the filtering engine with all the loaded rules
type Engine struct {
}

// Parse parses the filtering rules and creates a filtering engine of them
func Parse(rules string) (*Engine, error) {
	return &Engine{}, nil
}

// Match matches the specified request and looks for a matching filtering rule
func (e *Engine) Match(r *Request) (bool, *FilterRule) {
	return false, nil
}
