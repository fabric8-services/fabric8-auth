package recorder

import (
	"encoding/json"
	"github.com/dnaeon/go-vcr/cassette"
	"github.com/dnaeon/go-vcr/recorder"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/notification/client"
	goauuid "github.com/goadesign/goa/uuid"
	"github.com/satori/go.uuid"
	"net/http"
	"strings"
)

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

		if messageUUID, e := goauuid.FromString(messageID.String()); e == nil && payload.Data != nil {
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

// WithNotifyRequestPayloadMatcher an option to specify the RequestPayload matcher for the recorder
func WithNotifyRequestPayloadMatcher(messageID *uuid.UUID) Option {
	return func(r *recorder.Recorder) {
		r.SetMatcher(NotifyRequestPayloadMatcher(messageID))
	}
}
