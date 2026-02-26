package proxy

import (
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/urlfilter/rules"
)

// Session contains all the necessary data to filter requests and responses.
// It also contains the current state of the request.  Throughout the HTTP
// request lifetime, session data is updated with new information.
//
// There are two main stages of the HTTP request lifetime:
//  1. Received the HTTP request headers.
//     At this point, we can find all the rules matching the request using what
//     we know.  We assume the resource type by URL and "Accept" headers and
//     look for matching rules.  If there's a match, and the request should be
//     blocked, we simply block it.  Otherwise, we continue the HTTP request
//     execution.
//  2. Received the HTTP response headers.
//     At this point we've got the content-type header so we know for sure what
//     type of resource we're dealing with. We are looking for matching rules
//     again, and update them.
//     The possible outcomes are:
//
// 2.1. The request must be blocked.
// 2.2. The response must be modified (with a $replace or a $csp rule, for
// instance).
// 2.3. This is an HTML response so we need to filter the response body and
// apply cosmetic filters.
// 2.4. We should continue execution and do nothing with the response.
type Session struct {
	// Request is the original request data.  It must not be nil.
	Request *rules.Request

	// HTTPRequest is the original HTTP request data.  It must not be nil.
	HTTPRequest *http.Request

	// HTTPResponse is the original HTTP response data.
	HTTPResponse *http.Response

	// Result is the filtering engine result.
	Result *rules.MatchingResult

	// ID is the session identifier.
	ID string

	// MediaType is MIME media type.
	MediaType string

	// Charset is the response charset (if it's possible to parse it from
	// content-type).
	Charset string
}

// NewSession returns properly initialized *Session.  req must not be nil.
func NewSession(id string, req *http.Request) (session *Session) {
	requestType := assumeRequestType(req, nil)

	return &Session{
		ID:          id,
		Request:     rules.NewRequest(req.URL.String(), req.Referer(), requestType),
		HTTPRequest: req,
	}
}

// SetResponse sets the response of this session.  Function can modify response
// type.  res must not be nil.
func (s *Session) SetResponse(res *http.Response) {
	s.HTTPResponse = res

	// Re-calculate RequestType once we have the response headers.
	s.Request.RequestType = assumeRequestType(s.HTTPRequest, s.HTTPResponse)

	contentType := res.Header.Get("Content-Type")
	mediaType, params, _ := mime.ParseMediaType(contentType)

	s.MediaType = mediaType
	if charset, ok := params["charset"]; ok {
		s.Charset = charset
	}
}

// assumeRequestType assumes request type from what we know at this point.  req
// must not be nil.
func assumeRequestType(req *http.Request, res *http.Response) (reqType rules.RequestType) {
	// Check for websocket handshakes.
	upgradeHeader := req.Header.Get("Upgrade")
	if upgradeHeader == "websocket" {
		return rules.TypeWebsocket
	}

	// Check for ping requests.
	// See https://html.spec.whatwg.org/multipage/links.html#the-ping-headers.
	pingHeader := req.Header.Get("Ping-To")
	if pingHeader != "" {
		return rules.TypePing
	}

	fetchDestHeader := req.Header.Get("Sec-Fetch-Dest")
	requestType := assumeRequestTypeFromFetchDest(fetchDestHeader)
	if requestType != rules.TypeOther {
		return requestType
	}

	if res != nil {
		contentType := res.Header.Get("Content-Type")
		mediaType, _, _ := mime.ParseMediaType(contentType)
		return assumeRequestTypeFromMediaType(mediaType)
	}

	acceptHeader := req.Header.Get("Accept")
	requestType = assumeRequestTypeFromMediaType(acceptHeader)

	if requestType == rules.TypeOther {
		// Try to get it from the URL.
		requestType = assumeRequestTypeFromURL(req.URL)
	}

	return requestType
}

// fetchDestValues maps Sec-Fetch-Dest header values to the corresponding
// resource types.  The list of the possible Sec-Fetch-Dest header values:
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Dest.
var fetchDestValues = map[string]rules.RequestType{
	"audio":         rules.TypeMedia,
	"audioworklet":  rules.TypeScript,
	"document":      rules.TypeDocument,
	"embed":         rules.TypeOther,
	"empty":         rules.TypeXmlhttprequest,
	"font":          rules.TypeFont,
	"frame":         rules.TypeSubdocument,
	"iframe":        rules.TypeSubdocument,
	"image":         rules.TypeImage,
	"manifest":      rules.TypeOther,
	"object":        rules.TypeObject,
	"paintworklet":  rules.TypeScript,
	"report":        rules.TypeOther,
	"script":        rules.TypeScript,
	"serviceworker": rules.TypeScript,
	"sharedworker":  rules.TypeScript,
	"style":         rules.TypeStylesheet,
	"track":         rules.TypeOther,
	"video":         rules.TypeMedia,
	"worker":        rules.TypeScript,
	"xslt":          rules.TypeOther,
}

// assumeRequestTypeFromFetchDest assumes the request type from the
// "Sec-Fetch-Dest" header.
func assumeRequestTypeFromFetchDest(fetchDest string) (reqType rules.RequestType) {
	requestType, ok := fetchDestValues[fetchDest]
	if !ok {
		return rules.TypeOther
	}

	return requestType
}

// requestTypes is a mapping of media type prefixes to request types.
var requestTypes = container.KeyValues[string, rules.RequestType]{
	// $document
	{Key: "application/xhtml", Value: rules.TypeDocument},
	// We should recognize m3u file as html (in terms of filtering), because m3u
	// play list can contains refs to video ads.  So if we recognize it as html
	// we can filter it and in particular apply replace rules.  For more details
	// see https://github.com/AdguardTeam/AdguardForWindows/issues/1428.
	// TODO(ameshkov): Save media type to session parameters.
	{Key: "audio/x-mpegURL", Value: rules.TypeDocument},
	{Key: "text/html", Value: rules.TypeDocument},
	// $stylesheet
	{Key: "text/css", Value: rules.TypeStylesheet},
	// $script
	{Key: "application/javascript", Value: rules.TypeScript},
	{Key: "application/x-javascript", Value: rules.TypeScript},
	{Key: "text/javascript", Value: rules.TypeScript},
	// $image
	{Key: "image/", Value: rules.TypeImage},
	// $object
	{Key: "application/x-shockwave-flash", Value: rules.TypeObject},
	// $font
	{Key: "application/font", Value: rules.TypeFont},
	{Key: "application/vnd.ms-fontobject", Value: rules.TypeFont},
	{Key: "application/x-font-", Value: rules.TypeFont},
	{Key: "font/", Value: rules.TypeFont},
	// $media
	{Key: "audio/", Value: rules.TypeMedia},
	{Key: "video/", Value: rules.TypeMedia},
	// $json
	{Key: "application/json", Value: rules.TypeXmlhttprequest},
	// $ping
	{Key: "text/ping", Value: rules.TypePing},
}

// assumeRequestTypeFromMediaType detects the content type from the specified
// media type.
func assumeRequestTypeFromMediaType(mediaType string) (reqType rules.RequestType) {
	for _, kv := range requestTypes {
		if strings.HasPrefix(mediaType, kv.Key) {
			return kv.Value
		}
	}

	return rules.TypeOther
}

// fileExtensions is a mapping of file extensions to request types.
var fileExtensions = map[string]rules.RequestType{
	// $script
	".js":     rules.TypeScript,
	".vbs":    rules.TypeScript,
	".coffee": rules.TypeScript,
	// $image
	".jpg":  rules.TypeImage,
	".jpeg": rules.TypeImage,
	".gif":  rules.TypeImage,
	".png":  rules.TypeImage,
	".tiff": rules.TypeImage,
	".psd":  rules.TypeImage,
	".ico":  rules.TypeImage,
	// $stylesheet
	".css":  rules.TypeStylesheet,
	".less": rules.TypeStylesheet,
	// $object
	".jar": rules.TypeObject,
	".swf": rules.TypeObject,
	// $media
	".wav":   rules.TypeMedia,
	".mp3":   rules.TypeMedia,
	".mp4":   rules.TypeMedia,
	".avi":   rules.TypeMedia,
	".flv":   rules.TypeMedia,
	".m3u":   rules.TypeMedia,
	".webm":  rules.TypeMedia,
	".mpeg":  rules.TypeMedia,
	".3gp":   rules.TypeMedia,
	".3g2":   rules.TypeMedia,
	".3gpp":  rules.TypeMedia,
	".3gpp2": rules.TypeMedia,
	".ogg":   rules.TypeMedia,
	".mov":   rules.TypeMedia,
	".qt":    rules.TypeMedia,
	".vbm":   rules.TypeMedia,
	".mkv":   rules.TypeMedia,
	".gifv":  rules.TypeMedia,
	// $font
	".ttf":   rules.TypeFont,
	".otf":   rules.TypeFont,
	".woff":  rules.TypeFont,
	".woff2": rules.TypeFont,
	".eot":   rules.TypeFont,
	// $xmlhttprequest
	".json": rules.TypeXmlhttprequest,
}

// assumeRequestTypeFromURL assumes the request type from the file extension.  u
// must not be nil.
func assumeRequestTypeFromURL(u *url.URL) (reqType rules.RequestType) {
	ext := path.Ext(u.Path)

	requestType, ok := fileExtensions[ext]
	if !ok {
		return rules.TypeOther
	}

	return requestType
}
