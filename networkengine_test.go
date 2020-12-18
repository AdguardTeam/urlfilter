package urlfilter

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/shirou/gopsutil/process"
	"github.com/stretchr/testify/assert"
)

const (
	testResourcesDir = "test"
	filterPath       = testResourcesDir + "/easylist.txt"
	requestsPath     = testResourcesDir + "/requests.json"
)

type testRequest struct {
	LineNumber  int
	Line        string
	URL         string `json:"url"`
	FrameURL    string `json:"frameUrl"`
	RequestType string `json:"cpt"`
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

func TestBenchNetworkEngine(t *testing.T) {
	debug.SetGCPercent(10)

	testRequests := loadRequests(t)
	assert.True(t, len(testRequests) > 0)
	var requests []*rules.Request
	for _, req := range testRequests {
		r := rules.NewRequest(req.URL, req.FrameURL, testGetRequestType(req.RequestType))
		requests = append(requests, r)
	}

	start := getRSS()
	log.Printf("RSS before loading rules - %d kB\n", start/1024)

	startParse := time.Now()
	engine := buildNetworkEngine(t)
	assert.NotNil(t, engine)
	defer engine.ruleStorage.Close()
	log.Printf("Elapsed on parsing rules: %v", time.Since(startParse))

	afterLoad := getRSS()
	log.Printf("RSS after loading rules - %d kB (%d kB diff)\n", afterLoad/1024, (afterLoad-start)/1024)

	totalMatches := 0
	totalElapsed := time.Duration(0)
	minElapsedMatch := time.Hour
	maxElapsedMatch := time.Duration(0)

	for i, req := range requests {
		if i != 0 && i%10000 == 0 {
			log.Printf("Processed %d requests", i)
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

	log.Printf("Total matches: %d", totalMatches)
	log.Printf("Total elapsed: %v", totalElapsed)
	log.Printf("Average per request: %v", time.Duration(int64(totalElapsed)/int64(len(requests))))
	log.Printf("Max per request: %v", maxElapsedMatch)
	log.Printf("Min per request: %v", minElapsedMatch)
	log.Printf("Storage cache length: %d", engine.ruleStorage.GetCacheSize())

	afterMatch := getRSS()
	log.Printf("RSS after matching - %d kB (%d kB diff)\n", afterMatch/1024, (afterMatch-afterLoad)/1024)
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

func buildNetworkEngine(t *testing.T) *NetworkEngine {
	filterBytes, err := ioutil.ReadFile(filterPath)
	if err != nil {
		t.Fatalf("cannot read %s", filterPath)
	}
	lists := []filterlist.RuleList{
		&filterlist.StringRuleList{
			ID:             1,
			RulesText:      string(filterBytes),
			IgnoreCosmetic: true,
		},
	}

	ruleStorage, err := filterlist.NewRuleStorage(lists)
	if err != nil {
		t.Fatalf("cannot initialize rule storage: %s", err)
	}
	engine := NewNetworkEngine(ruleStorage)
	log.Printf("Loaded %d rules from %s", engine.RulesCount, filterPath)

	return engine
}

func newTestRuleStorage(t *testing.T, listID int, rulesText string) *filterlist.RuleStorage {
	list := &filterlist.StringRuleList{
		ID:             listID,
		RulesText:      rulesText,
		IgnoreCosmetic: false,
	}
	ruleStorage, err := filterlist.NewRuleStorage([]filterlist.RuleList{list})
	if err != nil {
		t.Fatalf("cannot initialize rule storage: %s", err)
	}
	return ruleStorage
}

func loadRequests(t *testing.T) []testRequest {
	if _, err := os.Stat(requestsPath); os.IsNotExist(err) {
		err = unzip(requestsPath+".zip", testResourcesDir)
		if err != nil {
			t.Fatalf("cannot unzip %s.zip", requestsPath)
		}
	}

	file, err := os.Open(requestsPath)
	if err != nil {
		t.Fatalf("cannot load %s: %s", requestsPath, err)
	}
	defer file.Close()

	var requests []testRequest

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			var req testRequest
			err := json.Unmarshal([]byte(line), &req)
			if err == nil && isSupportedURL(req.URL) && isSupportedURL(req.FrameURL) {
				req.Line = line
				req.LineNumber = lineNumber
				requests = append(requests, req)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	log.Printf("Loaded %d requests from %s", len(requests), requestsPath)
	return requests
}

func unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer func() {
		if err := r.Close(); err != nil {
			panic(err)
		}
	}()

	_ = os.MkdirAll(dest, 0o755)

	// Closure to address file descriptors issue with all the deferred .Close() methods
	extractAndWriteFile := func(f *zip.File) error {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer func() {
			if err := rc.Close(); err != nil {
				panic(err)
			}
		}()

		path := filepath.Join(dest, f.Name)

		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(path, f.Mode())
		} else {
			_ = os.MkdirAll(filepath.Dir(path), f.Mode())
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return err
			}
			defer func() {
				if err := f.Close(); err != nil {
					panic(err)
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
		err := extractAndWriteFile(f)
		if err != nil {
			return err
		}
	}

	return nil
}

func getRSS() uint64 {
	proc, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		panic(err)
	}
	minfo, err := proc.MemoryInfo()
	if err != nil {
		panic(err)
	}
	return minfo.RSS
}
