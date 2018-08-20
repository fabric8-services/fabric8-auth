package recorder

import (
	"fmt"
	"os"

	"encoding/json"
	"github.com/dnaeon/go-vcr/cassette"
	"github.com/dnaeon/go-vcr/recorder"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/notification/client"
	uuid2 "github.com/goadesign/goa/uuid"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"net/http"
	"strings"
)

// Option an option to customize the recorder to create
type Option func(*recorder.Recorder)

// WithMatcher an option to specify a custom matcher for the recorder
func WithMatcher(matcher cassette.Matcher) Option {
	return func(r *recorder.Recorder) {
		r.SetMatcher(matcher)
	}
}

// WithNotifyRequestPayloadMatcher an option to specify the RequestPayload matcher for the recorder
func WithNotifyRequestPayloadMatcher(messageID *uuid.UUID) Option {
	return func(r *recorder.Recorder) {
		r.SetMatcher(NotifyRequestPayloadMatcher(messageID))
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

// JWTMatcher a cassette matcher that verifies the request method/URL and the subject of the token in the "Authorization" header.
func NotifyRequestPayloadMatcher(messageID *uuid.UUID) cassette.Matcher {
	return func(httpRequest *http.Request, cassetteRequest cassette.Request) bool {
		// check the request URI and method
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

		payload := client.SendNotifyPayload{}
		if err := json.NewDecoder(strings.NewReader(cassetteRequest.Body)).Decode(&payload); err != nil {
			log.Error(nil, map[string]interface{}{"error": err.Error()}, "Cassette request payload doesn't match with notification payload")
			return false
		}

		if messageUUID, e := uuid2.FromString(messageID.String()); e == nil && payload.Data != nil {
			return *payload.Data.ID == messageUUID

		}

		return false
	}
}

func NotifyRequestHeaderPayloadMatcher(messageID *uuid.UUID, requestID, saToken string) cassette.Matcher {
	return func(httpRequest *http.Request, cassetteRequest cassette.Request) bool {

		if NotifyRequestPayloadMatcher(messageID)(httpRequest, cassetteRequest) {
			authorization := httpRequest.Header.Get("Authorization")
			reqID := httpRequest.Header.Get("X-Request-Id")

			return "Bearer "+saToken == authorization && reqID == requestID
		}

		return false
	}
}
