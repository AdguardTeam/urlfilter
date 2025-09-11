package urlfilter

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testResourcesDir = "testdata"
	filterPath       = testResourcesDir + "/easylist.txt"
	requestsPath     = testResourcesDir + "/requests.json"
)

type testRequest struct {
	Line        string
	URL         string `json:"url"`
	FrameURL    string `json:"frameUrl"`
	RequestType string `json:"cpt"`
	LineNumber  int
}

func TestEmptyNetworkEngine(t *testing.T) {
	ruleStorage := newTestRuleStorage(t, 1, "")
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
	ruleStorage := newTestRuleStorage(t, -1, rulesText)
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
	ruleStorage := newTestRuleStorage(t, -1, rulesText)
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
	ruleStorage := newTestRuleStorage(t, -1, ruleText)
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
	ruleStorage := newTestRuleStorage(t, -1, ruleText)
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
	testRequests := loadRequests(b)
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
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/urlfilter
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkNetworkEngine_heapAlloc-16    	      16	 685767583 ns/op	  26823070 heap_after_compilation_bytes/op	  38823596 heap_after_matching_bytes/op	  17057441 heap_initial_bytes/op	51036463 B/op	  515101 allocs/op
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
			ID:             1,
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

func isSupportedURL(url string) bool {
	return url != "" && (strings.HasPrefix(url, "http") ||
		strings.HasPrefix(url, "ws"))
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
			ID:             1,
			IgnoreCosmetic: true,
		}),
	}

	ruleStorage, err := filterlist.NewRuleStorage(lists)
	require.NoError(tb, err)

	return NewNetworkEngine(ruleStorage)
}

func newTestRuleStorage(t *testing.T, listID int, rulesText string) *filterlist.RuleStorage {
	list := filterlist.NewString(&filterlist.StringConfig{
		RulesText: rulesText,
		ID:        listID,
	})
	ruleStorage, err := filterlist.NewRuleStorage([]filterlist.Interface{list})
	if err != nil {
		t.Fatalf("cannot initialize rule storage: %s", err)
	}
	return ruleStorage
}

// loadRequests loads requests for tests from the testdata.
func loadRequests(tb testing.TB) (requests []testRequest) {
	tb.Helper()

	if _, err := os.Stat(requestsPath); errors.Is(err, os.ErrNotExist) {
		err = unzip(requestsPath+".zip", testResourcesDir)
		if err != nil {
			tb.Fatalf("cannot unzip %s.zip", requestsPath)
		}
	}

	file, err := os.Open(requestsPath)
	if err != nil {
		tb.Fatalf("cannot load %s: %s", requestsPath, err)
	}
	testutil.CleanupAndRequireSuccess(tb, file.Close)

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			var req testRequest
			err = json.Unmarshal([]byte(line), &req)
			if err == nil && isSupportedURL(req.URL) && isSupportedURL(req.FrameURL) {
				req.Line = line
				req.LineNumber = lineNumber
				requests = append(requests, req)
			}
		}
	}

	if err = scanner.Err(); err != nil {
		tb.Fatal(err)
	}

	return requests
}

func unzip(src, dest string) (err error) {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer func() {
		if err = r.Close(); err != nil {
			panic(err)
		}
	}()

	_ = os.MkdirAll(dest, 0o755)

	// Closure to address file descriptors issue with all the deferred .Close() methods
	extractAndWriteFile := func(zipFile *zip.File) (err error) {
		var rc io.ReadCloser
		rc, err = zipFile.Open()
		if err != nil {
			return err
		}

		defer func() {
			if rcErr := rc.Close(); err != nil {
				panic(rcErr)
			}
		}()

		path := filepath.Join(dest, zipFile.Name)

		if zipFile.FileInfo().IsDir() {
			_ = os.MkdirAll(path, zipFile.Mode())
		} else {
			_ = os.MkdirAll(filepath.Dir(path), zipFile.Mode())

			var f *os.File
			f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zipFile.Mode())
			if err != nil {
				return err
			}
			defer func() {
				if cerr := f.Close(); cerr != nil {
					panic(cerr)
				}
			}()

			_, err = io.Copy(f, rc)
			if err != nil {
				return err
			}
		}
		return nil
	}

	for _, f := range r.File {
		err = extractAndWriteFile(f)
		if err != nil {
			return err
		}
	}

	return nil
}
