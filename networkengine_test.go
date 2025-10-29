package urlfilter_test

import (
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/urlfilter"
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

// testURL is a URL used for testing.
var testURL = &url.URL{
	Scheme: urlutil.SchemeHTTP,
	Host:   "example.org",
}

func TestEmptyNetworkEngine(t *testing.T) {
	ruleStorage := newTestRuleStorage(t, uftest.ListID1, "")
	engine := urlfilter.NewNetworkEngine(ruleStorage)
	r := rules.NewRequest(testURL, nil, rules.TypeOther)
	rule, ok := engine.Match(r)
	assert.False(t, ok)
	assert.Nil(t, rule)
}

func TestMatchWhitelistRule(t *testing.T) {
	r1 := "||example.org^$script"
	r2 := "@@http://example.org^"
	rulesText := strings.Join([]string{r1, r2}, "\n")
	ruleStorage := newTestRuleStorage(t, uftest.ListID1, rulesText)
	engine := urlfilter.NewNetworkEngine(ruleStorage)

	r := rules.NewRequest(testURL, nil, rules.TypeScript)
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
	engine := urlfilter.NewNetworkEngine(ruleStorage)

	r := rules.NewRequest(testURL, nil, rules.TypeOther)
	rule, ok := engine.Match(r)
	assert.True(t, ok)
	assert.NotNil(t, rule)
	assert.Equal(t, r2, rule.String())

	r = rules.NewRequest(&url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   "test1.example.org",
	}, nil, rules.TypeOther)
	rule, ok = engine.Match(r)
	assert.True(t, ok)
	assert.NotNil(t, rule)
	assert.Equal(t, r2, rule.String())

	r = rules.NewRequest(&url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   "test2.example.org",
	}, nil, rules.TypeOther)
	rule, ok = engine.Match(r)
	assert.True(t, ok)
	assert.NotNil(t, rule)
	assert.Equal(t, r1, rule.String())
}

func TestMatchSourceRule(t *testing.T) {
	ruleText := "|https://$image,media,script,third-party,domain=~feedback.pornhub.com|pornhub.com|redtube.com|redtube.com.br|tube8.com|tube8.es|tube8.fr|youporn.com|youporngay.com"
	ruleStorage := newTestRuleStorage(t, uftest.ListID1, ruleText)
	engine := urlfilter.NewNetworkEngine(ruleStorage)

	reqURL := &url.URL{
		Scheme: urlutil.SchemeHTTPS,
		Host:   "ci.phncdn.com",
		Path:   "videos/201809/25/184777011/original/(m=ecuKGgaaaa)(mh=VSmV9NL_iouBcWJJ)4.jpg",
	}
	sourceURL := &url.URL{
		Scheme:   urlutil.SchemeHTTPS,
		Host:     "www.pornhub.com",
		Path:     "view_video.php",
		RawQuery: "viewkey=ph5be89d11de4b0",
	}

	r := rules.NewRequest(reqURL, sourceURL, rules.TypeImage)
	rule, ok := engine.Match(r)
	assert.True(t, ok)
	assert.NotNil(t, rule)
}

func TestMatchSimplePattern(t *testing.T) {
	// Simple pattern rule
	ruleText := "_prebid_"
	ruleStorage := newTestRuleStorage(t, uftest.ListID1, ruleText)
	engine := urlfilter.NewNetworkEngine(ruleStorage)

	reqURL := &url.URL{
		Scheme:   urlutil.SchemeHTTPS,
		Host:     "ap.lijit.com",
		Path:     "/rtb/bid",
		RawQuery: "src=prebid_prebid_1.35.0",
	}
	sourceURL := &url.URL{
		Scheme: urlutil.SchemeHTTPS,
		Host:   "www.drudgereport.com",
	}

	r := rules.NewRequest(reqURL, sourceURL, rules.TypeXmlhttprequest)
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
	var matchingRequests []*rules.Request
	easyListRequests := uftest.ParseRequests(b)
	for _, req := range easyListRequests {
		req := rules.NewRequest(&req.URL.URL, req.FrameURL, reqTypeToInternal(req.RequestType))
		matchingRequests = append(matchingRequests, req)
	}

	nonMatchingRequests := []*rules.Request{
		rules.NewRequestForHostname("non-matching.example"),
	}

	benchCases := []struct {
		name          string
		wantMatchOnce require.BoolAssertionFunc
		requests      []*rules.Request
		numIter       int
	}{{
		name:          "1_matching",
		wantMatchOnce: require.True,
		requests:      matchingRequests,
		numIter:       1,
	}, {
		name:          "10_matching",
		wantMatchOnce: require.True,
		requests:      matchingRequests,
		numIter:       10,
	}, {
		name:          "100_matching",
		wantMatchOnce: require.True,
		requests:      matchingRequests,
		numIter:       100,
	}, {
		name:          "1_non_matching",
		wantMatchOnce: require.False,
		requests:      nonMatchingRequests,
		numIter:       1,
	}, {
		name:          "10_non_matching",
		wantMatchOnce: require.False,
		requests:      nonMatchingRequests,
		numIter:       10,
	}, {
		name:          "100_non_matching",
		wantMatchOnce: require.False,
		requests:      nonMatchingRequests,
		numIter:       100,
	}}

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			m := &networkEngineMeasurement{}

			b.ReportAllocs()
			for b.Loop() {
				m.run(b, bc.requests, bc.numIter, bc.wantMatchOnce)
			}

			n := float64(b.N)

			b.ReportMetric(m.initialSum/n, "heap_initial_bytes/op")
			b.ReportMetric(m.afterCompilationSum/n, "heap_after_compilation_bytes/op")
			b.ReportMetric(m.afterMatchingSum/n, "heap_after_matching_bytes/op")
		})
	}

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/urlfilter
	//	cpu: Apple M1 Pro
	//	BenchmarkNetworkEngine_heapAlloc/1_matching-8         	      21	  51336286 ns/op	  12020605 heap_after_compilation_bytes/op	  12455160 heap_after_matching_bytes/op	   1159396 heap_initial_bytes/op	39397702 B/op	  361864 allocs/op
	//	BenchmarkNetworkEngine_heapAlloc/10_matching-8        	       7	 166036208 ns/op	  11613346 heap_after_compilation_bytes/op	  12189706 heap_after_matching_bytes/op	   1207706 heap_initial_bytes/op	39583158 B/op	  362703 allocs/op
	//	BenchmarkNetworkEngine_heapAlloc/100_matching-8       	       1	1304518750 ns/op	  13763472 heap_after_compilation_bytes/op	  13469504 heap_after_matching_bytes/op	   1015992 heap_initial_bytes/op	40647016 B/op	  373282 allocs/op
	//	BenchmarkNetworkEngine_heapAlloc/1_non_matching-8     	      34	  33701776 ns/op	  12223364 heap_after_compilation_bytes/op	  12246164 heap_after_matching_bytes/op	   1043357 heap_initial_bytes/op	35642842 B/op	  335216 allocs/op
	//	BenchmarkNetworkEngine_heapAlloc/10_non_matching-8    	      33	  34367210 ns/op	  12046043 heap_after_compilation_bytes/op	  12068838 heap_after_matching_bytes/op	   1047029 heap_initial_bytes/op	35646567 B/op	  335218 allocs/op
	//	BenchmarkNetworkEngine_heapAlloc/100_non_matching-8   	      34	  35464178 ns/op	  11761235 heap_after_compilation_bytes/op	  11551277 heap_after_matching_bytes/op	   1052049 heap_initial_bytes/op	35652948 B/op	  335217 allocs/op
}

// networkEngineMeasurement emulates a life cycle of a network filtering engine.
type networkEngineMeasurement struct {
	initialSum          float64
	afterCompilationSum float64
	afterMatchingSum    float64
}

// run performs a network engine life cycle.  Items of requests must not be nil.
func (m *networkEngineMeasurement) run(
	tb testing.TB,
	requests []*rules.Request,
	numIter int,
	mustMatchOnce require.BoolAssertionFunc,
) {
	tb.Helper()

	runtime.GC()

	m.initialSum += heapAlloc()

	e := newTestNetworkEngine(tb)

	m.afterCompilationSum += heapAlloc()

	matchedOnce := false
	for range numIter {
		for _, req := range requests {
			_, ok := e.Match(req)
			matchedOnce = matchedOnce || ok
		}
	}

	mustMatchOnce(tb, matchedOnce)

	m.afterMatchingSum += heapAlloc()
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

	engine := urlfilter.NewNetworkEngine(ruleStorage)

	f.Fuzz(func(t *testing.T, host string) {
		assert.NotPanics(t, func() {
			_, _ = engine.Match(rules.NewRequestForHostname(host))
		})
	})
}

// newTestNetworkEngine returns a new *NetworkEngine initialized with the rules
// from EasyList.
func newTestNetworkEngine(tb testing.TB) (engine *urlfilter.NetworkEngine) {
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

	s, err := filterlist.NewRuleStorage(lists)
	require.NoError(tb, err)

	return urlfilter.NewNetworkEngine(s)
}
