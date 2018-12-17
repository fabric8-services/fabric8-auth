package recorder

import (
	"encoding/json"
	"github.com/dnaeon/go-vcr/cassette"
	"github.com/dnaeon/go-vcr/recorder"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-cluster-client/cluster"
	"net/http"
	"strings"
)

type RequestParamMatcher interface {
	MatchClusterURL(r cassette.Request, url string) bool
	RequestMatcher(clusterURL string) cassette.Matcher
}

type LinkIdentityToClusterMatcher struct {
	DefaultRequestMatcher
}

func (m LinkIdentityToClusterMatcher) MatchClusterURL(r cassette.Request, url string) bool {
	payload := cluster.LinkIdentityToClusterData{}
	if err := json.NewDecoder(strings.NewReader(r.Body)).Decode(&payload); err != nil {
		log.Error(nil, map[string]interface{}{"error": err.Error()}, "Cassette request payload doesn't match with LinkIdentityToClusterData payload")
		return false
	}

	if payload.ClusterURL != "" {
		return payload.ClusterURL == url
	}
	return false
}

func (m LinkIdentityToClusterMatcher) RequestMatcher(clusterURL string) cassette.Matcher {
	return func(httpRequest *http.Request, cassetteRequest cassette.Request) bool {
		if ok := m.RequestMethodAndURLMatch(httpRequest, cassetteRequest); !ok {
			return ok
		}

		if m.MatchClusterURL(cassetteRequest, clusterURL) {
			return m.HeaderMatch(httpRequest, cassetteRequest)
		}

		return false
	}
}

type UnLinkIdentityToClusterMatcher struct {
	DefaultRequestMatcher
}

func (m UnLinkIdentityToClusterMatcher) MatchClusterURL(r cassette.Request, url string) bool {
	payload := cluster.UnLinkIdentityToClusterdata{}
	if err := json.NewDecoder(strings.NewReader(r.Body)).Decode(&payload); err != nil {
		log.Error(nil, map[string]interface{}{"error": err.Error()}, "Cassette request payload doesn't match with UnLinkIdentityToClusterdata payload")
		return false
	}

	if payload.ClusterURL != "" {
		return payload.ClusterURL == url
	}
	return false
}

func (m UnLinkIdentityToClusterMatcher) RequestMatcher(clusterURL string) cassette.Matcher {
	return func(httpRequest *http.Request, cassetteRequest cassette.Request) bool {
		if ok := m.RequestMethodAndURLMatch(httpRequest, cassetteRequest); !ok {
			return ok
		}

		if m.MatchClusterURL(cassetteRequest, clusterURL) {
			return m.HeaderMatch(httpRequest, cassetteRequest)
		}

		return false
	}
}

// WithLinkIdentityToClusterRequestPayloadMatcher an option to specify the RequestPayload matcher for the recorder
func WithLinkIdentityToClusterRequestPayloadMatcher(clusterURL, requestID, saToken string) Option {
	linkIdentityToClusterMatcher := &LinkIdentityToClusterMatcher{DefaultRequestMatcher{requestID: requestID, saToken: saToken}}

	return func(r *recorder.Recorder) {
		r.SetMatcher(linkIdentityToClusterMatcher.RequestMatcher(clusterURL))
	}
}

// WithLinkIdentityToClusterRequestPayloadMatcher an option to specify the RequestPayload matcher for the recorder
func WithUnLinkIdentityToClusterRequestPayloadMatcher(clusterURL, requestID, saToken string) Option {
	unLinkIdentityToClusterMatcher := &UnLinkIdentityToClusterMatcher{DefaultRequestMatcher{requestID: requestID, saToken: saToken}}

	return func(r *recorder.Recorder) {
		r.SetMatcher(unLinkIdentityToClusterMatcher.RequestMatcher(clusterURL))
	}
}
