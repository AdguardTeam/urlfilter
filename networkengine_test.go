package urlfilter

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/shirou/gopsutil/v3/process"
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
	URL         *urlutil.URL `json:"url"`
	FrameURL    *urlutil.URL `json:"frameUrl"`
	RequestType string       `json:"cpt"`
	LineNumber  int
}

// testURL is a URL used for testing.
var testURL = &url.URL{
	Scheme: urlutil.SchemeHTTP,
	Host:   "example.org",
}

func TestEmptyNetworkEngine(t *testing.T) {
	t.Parallel()

	ruleStorage := newTestRuleStorage(t, 1, "")
	engine := NewNetworkEngine(ruleStorage)
	r := rules.NewRequest(testURL, nil, rules.TypeOther)
	rule, ok := engine.Match(r)
	assert.False(t, ok)
	assert.Nil(t, rule)
}

func TestMatchWhitelistRule(t *testing.T) {
	t.Parallel()

	r1 := "||example.org^$script"
	r2 := "@@http://example.org^"
	rulesText := strings.Join([]string{r1, r2}, "\n")
	ruleStorage := newTestRuleStorage(t, -1, rulesText)
	engine := NewNetworkEngine(ruleStorage)

	r := rules.NewRequest(testURL, nil, rules.TypeScript)
	rule, ok := engine.Match(r)
	assert.True(t, ok)

	require.NotNil(t, rule)
	assert.Equal(t, r2, rule.Text())
}

func TestMatchImportantRule(t *testing.T) {
	t.Parallel()

	r1 := "||test2.example.org^$important"
	r2 := "@@||example.org^"
	r3 := "||test1.example.org^"
	rulesText := strings.Join([]string{r1, r2, r3}, "\n")
	ruleStorage := newTestRuleStorage(t, -1, rulesText)
	engine := NewNetworkEngine(ruleStorage)

	r := rules.NewRequest(testURL, nil, rules.TypeOther)
	rule, ok := engine.Match(r)
	assert.True(t, ok)

	require.NotNil(t, rule)
	assert.Equal(t, r2, rule.Text())

	r = rules.NewRequest(&url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   "test1.example.org",
	}, nil, rules.TypeOther)
	rule, ok = engine.Match(r)
	assert.True(t, ok)

	require.NotNil(t, rule)
	assert.Equal(t, r2, rule.Text())

	r = rules.NewRequest(&url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   "test2.example.org",
	}, nil, rules.TypeOther)
	rule, ok = engine.Match(r)
	assert.True(t, ok)

	require.NotNil(t, rule)
	assert.Equal(t, r1, rule.Text())
}

func TestNetworkEngine_Match_sourceRule(t *testing.T) {
	t.Parallel()

	ruleText := "|https://$image,media,script,third-party,domain=" +
		"~feedback.pornhub.com|pornhub.com|redtube.com|redtube.com.br|tube8.com|" +
		"tube8.es|tube8.fr|youporn.com|youporngay.com"
	ruleStorage := newTestRuleStorage(t, -1, ruleText)
	engine := NewNetworkEngine(ruleStorage)

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

	require.NotNil(t, rule)
	assert.Equal(t, ruleText, rule.Text())
}

func TestNetworkEngine_Match_simplePattern(t *testing.T) {
	t.Parallel()

	ruleText := "_prebid_"
	ruleStorage := newTestRuleStorage(t, -1, ruleText)
	engine := NewNetworkEngine(ruleStorage)

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

	require.NotNil(t, rule)
	assert.Equal(t, ruleText, rule.Text())
}

// TODO(a.garipov):  Consider removing and replacing with tests similar to
// [BenchmarkDNSEngine_heapAlloc].
func TestBenchNetworkEngine(t *testing.T) {
	// TODO(d.kolyshev):  !! Remove this skip.
	t.Skip()

	debug.SetGCPercent(10)

	testRequests := loadRequests(t)
	assert.True(t, len(testRequests) > 0)
	var requests []*rules.Request
	for _, req := range testRequests {
		r := rules.NewRequest(&req.URL.URL, &req.FrameURL.URL, testGetRequestType(req.RequestType))
		requests = append(requests, r)
	}

	startHeap, startRSS := alloc(t)
	t.Logf(
		"Allocated before loading rules (heap/RSS, kiB): %d/%d",
		startHeap,
		startRSS,
	)

	startParse := time.Now()
	engine := newTestNetworkEngine(t)
	assert.NotNil(t, engine)
	testutil.CleanupAndRequireSuccess(t, engine.ruleStorage.Close)

	t.Logf("Elapsed on parsing rules: %v", time.Since(startParse))

	loadHeap, loadRSS := alloc(t)
	t.Logf(
		"Allocated after loading rules (heap/RSS, kiB): %d/%d (%d/%d diff)",
		loadHeap,
		loadRSS,
		loadHeap-startHeap,
		loadRSS-startRSS,
	)

	totalMatches := 0
	totalElapsed := time.Duration(0)
	minElapsedMatch := time.Hour
	maxElapsedMatch := time.Duration(0)

	for i, req := range requests {
		if i != 0 && i%10000 == 0 {
			t.Logf("Processed %d requests", i)
		}

		startMatch := time.Now()
		rule, ok := engine.Match(req)
		elapsedMatch := time.Since(startMatch)
		totalElapsed += elapsedMatch
		if elapsedMatch > maxElapsedMatch {
			maxElapsedMatch = elapsedMatch
		}
		if elapsedMatch < minElapsedMatch {
			minElapsedMatch = elapsedMatch
		}

		if ok && !rule.Whitelist {
			totalMatches++
		}
	}

	t.Logf("Total matches: %d", totalMatches)
	t.Logf("Total elapsed: %v", totalElapsed)
	t.Logf("Average per request: %v", time.Duration(int64(totalElapsed)/int64(len(requests))))
	t.Logf("Max per request: %v", maxElapsedMatch)
	t.Logf("Min per request: %v", minElapsedMatch)
	//lint:ignore SA1019 TODO(a.garipov): Remove the method
	t.Logf("Storage cache length: %d", engine.ruleStorage.GetCacheSize())

	matchHeap, matchRSS := alloc(t)
	t.Logf(
		"Allocated after matching (heap/RSS, kiB): %d/%d (%d/%d diff)",
		matchHeap,
		matchRSS,
		matchHeap-loadHeap,
		matchRSS-loadRSS,
	)
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
			req := rules.NewRequestForURL(&url.URL{
				Scheme: urlutil.SchemeHTTP,
				Host:   host,
			})
			_, _ = engine.Match(req)
		})
	})
}

// assumeRequestType converts string value from requests.json to RequestType
// This maps puppeteer types to WebRequest types
func testGetRequestType(t string) rules.RequestType {
	switch t {
	case "document":
		// Consider document requests as sub_document. This is because the request
		// dataset does not contain sub_frame or main_frame but only 'document'.
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

func loadRequests(t testing.TB) []testRequest {
	if _, err := os.Stat(requestsPath); errors.Is(err, os.ErrNotExist) {
		err = unzip(requestsPath+".zip", testResourcesDir)
		if err != nil {
			t.Fatalf("cannot unzip %s.zip", requestsPath)
		}
	}

	file, err := os.Open(requestsPath)
	if err != nil {
		t.Fatalf("cannot load %s: %s", requestsPath, err)
	}
	testutil.CleanupAndRequireSuccess(t, file.Close)

	var requests []testRequest

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			var req testRequest
			err = json.Unmarshal([]byte(line), &req)
			if err == nil && isSupportedURL(req.URL.String()) && isSupportedURL(req.FrameURL.String()) {
				req.Line = line
				req.LineNumber = lineNumber
				requests = append(requests, req)
			}
		}
	}

	if err = scanner.Err(); err != nil {
		t.Fatal(err)
	}

	log.Printf("Loaded %d requests from %s", len(requests), requestsPath)
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

// alloc returns the heap and RSS memory sizes, in kibibytes.
func alloc(t testing.TB) (heap, rss uint64) {
	p, err := process.NewProcess(int32(os.Getpid()))
	require.NoError(t, err)

	mi, err := p.MemoryInfo()
	require.NoError(t, err)

	ms := &runtime.MemStats{}
	runtime.ReadMemStats(ms)

	return ms.Alloc / 1024, mi.RSS / 1024
}
