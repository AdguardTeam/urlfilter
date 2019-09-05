package urlfilter

// Engine represents the filtering engine with all the loaded rules
type Engine struct {
	networkEngine  *NetworkEngine
	cosmeticEngine *CosmeticEngine
}

// NewEngine parses the filtering rules and creates a filtering engine of them
func NewEngine(s *RuleStorage) (*Engine, error) {
	return &Engine{}, nil
}

func (e *Engine) Match(r *Request) {

}
