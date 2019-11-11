package proxy

import (
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/AdguardTeam/urlfilter"
)

// Session contains all the necessary data to filter requests and responses.
// It also contains the current state of the request.
// Throughout the HTTP request lifetime, session data is updated with new information.
//
// There are two main stages of the HTTP request lifetime:
// 1. Received the HTTP request headers.
//    At this point, we can find all the rules matching the request using what we know.
//    We assume the resource type by URL and "Accept" headers and look for matching rules.
//    If there's a match, and the request should be blocked, we simply block it.
//    Otherwise, we continue the HTTP request execution.
// 2. Received the HTTP response headers.
//    At this point we've got the content-type header so we know for sure what type
//    of resource we're dealing with. We are looking for matching rules again, and
//    update them.
//    The possible outcomes are:
// 2.1. The request must be blocked.
// 2.2. The response must be modified (with a $replace or a $csp rule, for instance).
// 2.3. This is an HTML response so we need to filter the response body and apply cosmetic filters.
// 2.4. We should continue execution and do nothing with the response.
type Session struct {
	ID      string             // Session identifier
	Request *urlfilter.Request // Request data

	HTTPRequest  *http.Request  // HTTP request data
	HTTPResponse *http.Response // HTTP response data

	MediaType string // Mime media type
	Charset   string // Response charset (if it's possible to parse it from content-type)

	Result urlfilter.MatchingResult // Filtering engine result
}

// NewSession creates a new instance of the Session struct and initializes it.
// id -- unique session identifier
// req -- HTTP request data
func NewSession(id string, req *http.Request) *Session {
	requestType := assumeRequestType(req, nil)

	s := Session{
		ID:          id,
		Request:     urlfilter.NewRequest(req.URL.String(), req.Referer(), requestType),
		HTTPRequest: req,
	}

	return &s
}

// SetResponse sets the response of this session
// This can also end in changing the request type
func (s *Session) SetResponse(res *http.Response) {
	s.HTTPResponse = res

	// Re-calculate RequestType once we have the response headers
	s.Request.RequestType = assumeRequestType(s.HTTPRequest, s.HTTPResponse)

	contentType := res.Header.Get("Content-Type")
	mediaType, params, _ := mime.ParseMediaType(contentType)

	s.MediaType = mediaType
	if charset, ok := params["charset"]; ok {
		s.Charset = charset
	}
}

// assumeRequestType assumes request type from what we know at this point.
// req -- HTTP request
// res -- HTTP response or null if we don't know it at the moment
func assumeRequestType(req *http.Request, res *http.Response) urlfilter.RequestType {
	if res != nil {
		contentType := res.Header.Get("Content-Type")
		mediaType, _, _ := mime.ParseMediaType(contentType)
		return assumeRequestTypeFromMediaType(mediaType)
	}

	acceptHeader := req.Header.Get("Accept")
	requestType := assumeRequestTypeFromMediaType(acceptHeader)

	if requestType == urlfilter.TypeOther {
		// Try to get it from the URL
		requestType = assumeRequestTypeFromURL(req.URL)
	}

	return requestType
}

// assumeRequestTypeFromMediaType tries to detect the content type from the specified media type
func assumeRequestTypeFromMediaType(mediaType string) urlfilter.RequestType {
	switch {
	// $document
	case strings.Index(mediaType, "application/xhtml") == 0:
		return urlfilter.TypeDocument
	// We should recognize m3u file as html (in terms of filtering), because m3u play list can contains refs to video ads.
	// So if we recognize it as html we can filter it and in particular apply replace rules
	// for more details see https://github.com/AdguardTeam/AdguardForWindows/issues/1428
	// TODO: Change this -- save media type to session parameters
	case strings.Index(mediaType, "audio/x-mpegURL") == 0:
		return urlfilter.TypeDocument
	case strings.Index(mediaType, "text/html") == 0:
		return urlfilter.TypeDocument
	// $stylesheet
	case strings.Index(mediaType, "text/css") == 0:
		return urlfilter.TypeStylesheet
	// $script
	case strings.Index(mediaType, "application/javascript") == 0:
		return urlfilter.TypeScript
	case strings.Index(mediaType, "application/x-javascript") == 0:
		return urlfilter.TypeScript
	case strings.Index(mediaType, "text/javascript") == 0:
		return urlfilter.TypeScript
	// $image
	case strings.Index(mediaType, "image/") == 0:
		return urlfilter.TypeImage
	// $object
	case strings.Index(mediaType, "application/x-shockwave-flash") == 0:
		return urlfilter.TypeObject
	// $font
	case strings.Index(mediaType, "application/font") == 0:
		return urlfilter.TypeFont
	case strings.Index(mediaType, "application/vnd.ms-fontobject") == 0:
		return urlfilter.TypeFont
	case strings.Index(mediaType, "application/x-font-") == 0:
		return urlfilter.TypeFont
	case strings.Index(mediaType, "font/") == 0:
		return urlfilter.TypeFont
	// $media
	case strings.Index(mediaType, "audio/") == 0:
		return urlfilter.TypeMedia
	case strings.Index(mediaType, "video/") == 0:
		return urlfilter.TypeMedia
	// $json
	case strings.Index(mediaType, "application/json") == 0:
		return urlfilter.TypeXmlhttprequest
	}

	return urlfilter.TypeOther
}

var fileExtensions = map[string]urlfilter.RequestType{
	// $script
	".js":     urlfilter.TypeScript,
	".vbs":    urlfilter.TypeScript,
	".coffee": urlfilter.TypeScript,
	// $image
	".jpg":  urlfilter.TypeImage,
	".jpeg": urlfilter.TypeImage,
	".gif":  urlfilter.TypeImage,
	".png":  urlfilter.TypeImage,
	".tiff": urlfilter.TypeImage,
	".psd":  urlfilter.TypeImage,
	".ico":  urlfilter.TypeImage,
	// $stylesheet
	".css":  urlfilter.TypeStylesheet,
	".less": urlfilter.TypeStylesheet,
	// $object
	".jar": urlfilter.TypeObject,
	".swf": urlfilter.TypeObject,
	// $media
	".wav":   urlfilter.TypeMedia,
	".mp3":   urlfilter.TypeMedia,
	".mp4":   urlfilter.TypeMedia,
	".avi":   urlfilter.TypeMedia,
	".flv":   urlfilter.TypeMedia,
	".m3u":   urlfilter.TypeMedia,
	".webm":  urlfilter.TypeMedia,
	".mpeg":  urlfilter.TypeMedia,
	".3gp":   urlfilter.TypeMedia,
	".3g2":   urlfilter.TypeMedia,
	".3gpp":  urlfilter.TypeMedia,
	".3gpp2": urlfilter.TypeMedia,
	".ogg":   urlfilter.TypeMedia,
	".mov":   urlfilter.TypeMedia,
	".qt":    urlfilter.TypeMedia,
	".vbm":   urlfilter.TypeMedia,
	".mkv":   urlfilter.TypeMedia,
	".gifv":  urlfilter.TypeMedia,
	// $font
	".ttf":   urlfilter.TypeFont,
	".otf":   urlfilter.TypeFont,
	".woff":  urlfilter.TypeFont,
	".woff2": urlfilter.TypeFont,
	".eot":   urlfilter.TypeFont,
	// $xmlhttprequest
	".json": urlfilter.TypeXmlhttprequest,
}

// assumeRequestTypeFromURL assumes the request type from the file extension
func assumeRequestTypeFromURL(url *url.URL) urlfilter.RequestType {
	ext := path.Ext(url.Path)

	requestType, ok := fileExtensions[ext]
	if !ok {
		return urlfilter.TypeOther
	}

	return requestType
}
