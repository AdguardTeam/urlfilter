package urlfilter

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	testResourcesDir = "test"
	filterPath       = testResourcesDir + "/easylist.txt"
	requestsPath     = testResourcesDir + "/requests.json"
)

type testRequest struct {
	URL         string `json:"url"`
	FrameUrl    string `json:"frameUrl"`
	RequestType string `json:"cpt"`
}

func TestLoadNetworkEngine(t *testing.T) {
	engine := buildNetworkEngine(t)
	assert.NotNil(t, engine)
}

func TestBenchNetworkEngine(t *testing.T) {
	requests := loadRequests(t)
	assert.True(t, len(requests) > 0)

	startParse := time.Now()
	engine := buildNetworkEngine(t)
	assert.NotNil(t, engine)
	log.Printf("Elapsed on parsing rules: %v", time.Since(startParse))

	totalMatches := 0
	elapsed := time.Duration(0)

	for i, req := range requests {
		if i != 0 && i%10000 == 0 {
			log.Printf("Processed %d requests", i)
		}

		r := NewRequest(req.URL, req.FrameUrl, getRequestType(req.RequestType))

		start := time.Now()
		ok, rule := engine.Match(r)
		elapsed += time.Since(start)

		if ok && !rule.Whitelist {
			totalMatches++
		}
	}

	log.Printf("Total matches: %d", totalMatches)
	log.Printf("Total elapsed: %v", elapsed)
	log.Printf("Average per request: %v", time.Duration(int64(elapsed)/int64(len(requests))))
}

// getRequestType converts string value from requests.json to RequestType
func getRequestType(t string) RequestType {
	switch t {
	case "main_frame":
		return TypeDocument
	case "sub_frame":
		return TypeSubdocument
	case "font":
		return TypeFont
	case "image", "imageset":
		return TypeImage
	case "media":
		return TypeMedia
	case "object":
		return TypeObject
	case "object_subrequest":
		return TypeObjectSubrequest
	case "script":
		return TypeScript
	case "stylesheet":
		return TypeStylesheet
	case "websocket":
		return TypeWebsocket
	case "xmlhttprequest":
		return TypeXmlhttprequest
	default:
		return TypeOther
	}
}

func isSupportedURL(url string) bool {
	return url != "" && (strings.HasPrefix(url, "http") ||
		strings.HasPrefix(url, "ws"))
}

func buildNetworkEngine(t *testing.T) *NetworkEngine {
	if _, err := os.Stat(filterPath); os.IsNotExist(err) {
		err = unzip(filterPath+".zip", testResourcesDir)
		if err != nil {
			t.Fatalf("cannot unzip %s.zip", filterPath)
		}
	}

	file, err := os.Open(filterPath)
	if err != nil {
		t.Fatalf("cannot load %s: %s", filterPath, err)
	}
	defer file.Close()

	var rules []*NetworkRule

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line != "" &&
			!strings.HasPrefix(line, "!") &&
			strings.Index(line, "##") == -1 &&
			strings.Index(line, "#@#") == -1 &&
			strings.Index(line, "#%#") == -1 &&
			strings.Index(line, "#?#") == -1 &&
			strings.Index(line, "#$#") == -1 &&
			strings.Index(line, "$$") == -1 {

			rule, err := NewNetworkRule(line, 0)
			if err == nil {
				rules = append(rules, rule)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	log.Printf("Loaded %d rules from %s", len(rules), filterPath)
	return NewNetworkEngine(rules)
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
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			var req testRequest
			err := json.Unmarshal([]byte(line), &req)
			if err == nil && isSupportedURL(req.URL) {
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

	os.MkdirAll(dest, 0755)

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
			os.MkdirAll(path, f.Mode())
		} else {
			os.MkdirAll(filepath.Dir(path), f.Mode())
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
