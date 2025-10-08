package urlfilter

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/internal/uftest"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testResourcesDir = "testdata"
	filterPath       = testResourcesDir + "/easylist.txt"
)

func TestEmptyNetworkEngine(t *testing.T) {
	ruleStorage := newTestRuleStorage(t, uftest.ListID1, "")
	engine := NewNetworkEngine(ruleStorage)
	r := rules.NewRequest("http://example.org/", "", rules.TypeOther)
	rule, ok := engine.Match(r)
	assert.False(t, ok)
	assert.Nil(t, rule)
}

func TestMatchWhitelistRule(t *testing.T) {
	r1 := "||example.org^$script"
	r2 := "@@http://example.org^"
	rulesText := strings.Join([]string{r1, r2}, "\n")
	ruleStorage := newTestRuleStorage(t, uftest.ListID1, rulesText)
	engine := NewNetworkEngine(ruleStorage)

	r := rules.NewRequest("http://example.org/", "", rules.TypeScript)
	rule, ok := engine.Match(r)
	assert.True(t, ok)
	assert.NotNil(t, rule)
	assert.Equal(t, r2, rule.String())
}

func TestMatchImportantRule(t *testing.T) {
	r1 := "||test2.example.org^$important"
	r2 := "@@||example.org^"
	r3 := "||test1.example.org^"
	rulesText := strings.Join([]string{r1, r2, r3}, "\n")
	ruleStorage := newTestRuleStorage(t, uftest.ListID1, rulesText)
	engine := NewNetworkEngine(ruleStorage)

	r := rules.NewRequest("http://example.org/", "", rules.TypeOther)
	rule, ok := engine.Match(r)
	assert.True(t, ok)
	assert.NotNil(t, rule)
	assert.Equal(t, r2, rule.String())

	r = rules.NewRequest("http://test1.example.org/", "", rules.TypeOther)
	rule, ok = engine.Match(r)
	assert.True(t, ok)
	assert.NotNil(t, rule)
	assert.Equal(t, r2, rule.String())

	r = rules.NewRequest("http://test2.example.org/", "", rules.TypeOther)
	rule, ok = engine.Match(r)
	assert.True(t, ok)
	assert.NotNil(t, rule)
	assert.Equal(t, r1, rule.String())
}

func TestMatchSourceRule(t *testing.T) {
	ruleText := "|https://$image,media,script,third-party,domain=~feedback.pornhub.com|pornhub.com|redtube.com|redtube.com.br|tube8.com|tube8.es|tube8.fr|youporn.com|youporngay.com"
	ruleStorage := newTestRuleStorage(t, uftest.ListID1, ruleText)
	engine := NewNetworkEngine(ruleStorage)

	url := "https://ci.phncdn.com/videos/201809/25/184777011/original/(m=ecuKGgaaaa)(mh=VSmV9NL_iouBcWJJ)4.jpg"
	sourceURL := "https://www.pornhub.com/view_video.php?viewkey=ph5be89d11de4b0"

	r := rules.NewRequest(url, sourceURL, rules.TypeImage)
	rule, ok := engine.Match(r)
	assert.True(t, ok)
	assert.NotNil(t, rule)
}

func TestMatchSimplePattern(t *testing.T) {
	// Simple pattern rule
	ruleText := "_prebid_"
	ruleStorage := newTestRuleStorage(t, uftest.ListID1, ruleText)
	engine := NewNetworkEngine(ruleStorage)

	url := "https://ap.lijit.com/rtb/bid?src=prebid_prebid_1.35.0"
	sourceURL := "https://www.drudgereport.com/"

	r := rules.NewRequest(url, sourceURL, rules.TypeXmlhttprequest)
	rule, ok := engine.Match(r)
	assert.True(t, ok)
	assert.NotNil(t, rule)
}

// BenchmarkNetworkEngine_heapAlloc is a benchmark used to measure changes in
// the heap-allocated memory during typical operation of a network engine.  It
// reports the following additional metrics:
//   - heap_initial_bytes/op: the average size of allocated heap objects before
//     doing anything.
//   - heap_after_compilation_bytes/op: the average size of allocated heap
//     objects after compiling rule lists.
//   - heap_after_matching_bytes/op: the average size of allocated heap objects
//     after matching a few requests with the engine.
//
// NOTE:  The precise values of the aforementioned metrics may vary from run to
// run.  Benchmark with --benchtime no less than 10s and --count no less than 10
// to get a better picture of the real changes in performance.
func BenchmarkNetworkEngine_heapAlloc(b *testing.B) {
	var requests []*rules.Request
	testRequests := uftest.ParseRequests(b)
	for _, req := range testRequests {
		req := rules.NewRequest(req.URL, req.FrameURL, reqTypeToInternal(req.RequestType))
		requests = append(requests, req)
	}

	m := &networkEngineMeasurement{}

	b.ReportAllocs()
	for b.Loop() {
		m.run(b, requests)
	}

	n := float64(b.N)

	b.ReportMetric(m.initialSum/n, "heap_initial_bytes/op")
	b.ReportMetric(m.afterCompilationSum/n, "heap_after_compilation_bytes/op")
	b.ReportMetric(m.afterMatchingSum/n, "heap_after_matching_bytes/op")

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/urlfilter
	//	cpu: Apple M3
	//	BenchmarkNetworkEngine_heapAlloc-8   	       3	 386104320 ns/op	  27992808 heap_after_compilation_bytes/op	  34492312 heap_after_matching_bytes/op	  16833339 heap_initial_bytes/op	53293706 B/op	  478824 allocs/op
}

// networkEngineMeasurement emulates a life cycle of a network filtering engine.
type networkEngineMeasurement struct {
	initialSum          float64
	afterCompilationSum float64
	afterMatchingSum    float64
}

// run performs a network engine life cycle.  Items of requests must not be nil.
func (m *networkEngineMeasurement) run(tb testing.TB, requests []*rules.Request) {
	tb.Helper()

	runtime.GC()

	m.initialSum += heapAlloc(tb)

	e := newTestNetworkEngine(tb)

	m.afterCompilationSum += heapAlloc(tb)

	for _, req := range requests {
		_, _ = e.Match(req)
	}

	m.afterMatchingSum += heapAlloc(tb)
}

// reqTypeToInternal converts a string value from requests.json to a valid
// RequestType.  This maps puppeteer types to WebRequest types.
func reqTypeToInternal(s string) (t rules.RequestType) {
	switch s {
	case "document":
		// Consider document requests as sub_document.  This is because the
		// request dataset does not contain sub_frame or main_frame but only
		// 'document'.
		return rules.TypeSubdocument
	case "stylesheet":
		return rules.TypeStylesheet
	case "font":
		return rules.TypeFont
	case "image":
		return rules.TypeImage
	case "media":
		return rules.TypeMedia
	case "script":
		return rules.TypeScript
	case "xhr", "fetch":
		return rules.TypeXmlhttprequest
	case "websocket":
		return rules.TypeWebsocket
	default:
		return rules.TypeOther
	}
}

func FuzzNetworkEngine_Match(f *testing.F) {
	for _, seed := range []string{
		"",
		" ",
		"\n",
		"1",
		"127.0.0.1",
		"example.test",
	} {
		f.Add(seed)
	}

	rulesText := "||example.test^"

	lists := []filterlist.Interface{
		filterlist.NewString(&filterlist.StringConfig{
			RulesText:      rulesText,
			ID:             uftest.ListID1,
			IgnoreCosmetic: true,
		}),
	}

	ruleStorage, err := filterlist.NewRuleStorage(lists)
	require.NoError(f, err)

	testutil.CleanupAndRequireSuccess(f, ruleStorage.Close)

	engine := NewNetworkEngine(ruleStorage)

	f.Fuzz(func(t *testing.T, host string) {
		assert.NotPanics(t, func() {
			_, _ = engine.Match(rules.NewRequestForHostname(host))
		})
	})
}

// newTestNetworkEngine returns a new NetworkEngine initialized with the rules
// from filterPath.
func newTestNetworkEngine(tb testing.TB) (engine *NetworkEngine) {
	tb.Helper()

	filterBytes, err := os.ReadFile(filterPath)
	require.NoError(tb, err)

	lists := []filterlist.Interface{
		filterlist.NewBytes(&filterlist.BytesConfig{
			RulesText:      filterBytes,
			ID:             uftest.ListID1,
			IgnoreCosmetic: true,
		}),
	}

	ruleStorage, err := filterlist.NewRuleStorage(lists)
	require.NoError(tb, err)

	return NewNetworkEngine(ruleStorage)
}

func newTestRuleStorage(t *testing.T, id rules.ListID, text string) (s *filterlist.RuleStorage) {
	list := filterlist.NewString(&filterlist.StringConfig{
		RulesText: text,
		ID:        id,
	})

	s, err := filterlist.NewRuleStorage([]filterlist.Interface{list})
	require.NoError(t, err)

	return s
}
