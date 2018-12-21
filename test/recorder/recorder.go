package recorder

import (
	"fmt"
	"os"

	"github.com/dnaeon/go-vcr/cassette"
	"github.com/dnaeon/go-vcr/recorder"
	"github.com/fabric8-services/fabric8-auth/log"
	errs "github.com/pkg/errors"
	"net/http"
)

// Option an option to customize the recorder to create
type Option func(*recorder.Recorder)

// WithMatcher an option to specify a custom matcher for the recorder
func WithMatcher(matcher cassette.Matcher) Option {
	return func(r *recorder.Recorder) {
		r.SetMatcher(matcher)
	}
}

// New creates a new recorder
func New(cassetteName string, options ...Option) (*recorder.Recorder, error) {
	_, err := os.Stat(fmt.Sprintf("%s.yaml", cassetteName))
	if err != nil {
		return nil, errs.Wrapf(err, "unable to find file '%s.yaml'", cassetteName)
	}
	r, err := recorder.New(cassetteName)
	if err != nil {
		return nil, errs.Wrapf(err, "unable to create recorder from file '%s.yaml'", cassetteName)
	}
	// custom cassette matcher that will compare the HTTP requests' token subject with the `sub` header of the recorded data (the yaml file)
	for _, opt := range options {
		opt(r)
	}
	return r, nil
}

// DefaultRequestMatcher to compare the request method, URL requestID, Service Account Token.
type DefaultRequestMatcher struct {
	saToken   string
	requestID string
}

// RequestMethodAndURLMatch matches request Method and URL
func (r DefaultRequestMatcher) RequestMethodAndURLMatch(httpRequest *http.Request, cassetteRequest cassette.Request) bool {
	if httpRequest.Method != cassetteRequest.Method ||
		(httpRequest.URL != nil && httpRequest.URL.String() != cassetteRequest.URL) {
		log.Debug(nil, map[string]interface{}{
			"httpRequest_method":     httpRequest.Method,
			"cassetteRequest_method": cassetteRequest.Method,
			"httpRequest_url":        httpRequest.URL,
			"cassetteRequest_url":    cassetteRequest.URL,
		}, "Cassette method/url doesn't match with the current request")
		return false
	}
	return true
}

// RequestMethodAndURLMatch matches requestID and Service Account Token
func (r DefaultRequestMatcher) HeaderMatch(httpRequest *http.Request, cassetteRequest cassette.Request) bool {
	authorization := httpRequest.Header.Get("Authorization")
	reqID := httpRequest.Header.Get("X-Request-Id")

	return "Bearer "+r.saToken == authorization && reqID == r.requestID
}

// WithDefaultMatcher an option to specify the custom matcher with requestID and Service Account Token for the recorder
func WithDefaultMatcher(requestID, saToken string) Option {
	matcher := &DefaultRequestMatcher{saToken, requestID}

	return func(r *recorder.Recorder) {
		r.SetMatcher(func(httpRequest *http.Request, cassetteRequest cassette.Request) bool {
			if ok := matcher.RequestMethodAndURLMatch(httpRequest, cassetteRequest); !ok {
				return ok
			}

			return matcher.HeaderMatch(httpRequest, cassetteRequest)
		})
	}
}
