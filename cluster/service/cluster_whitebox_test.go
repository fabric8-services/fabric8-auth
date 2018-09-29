package service

import (
	"context"
	"net/http"
	"testing"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-auth/test/recorder"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"
	tokentestsupport "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/fabric8-services/fabric8-auth/token"

	"github.com/dnaeon/go-vcr/cassette"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestCluster(t *testing.T) {
	suite.Run(t, &TestClusterSuite{})
}

type TestClusterSuite struct {
	testsuite.UnitTestSuite
	cs      service.ClusterService
	tm      token.Manager
	saToken string
}

func (s *TestClusterSuite) SetupSuite() {
	s.UnitTestSuite.SetupSuite()
	var err error
	s.tm, err = token.DefaultManager(s.Config)
	require.NoError(s.T(), err)
	s.saToken = s.tm.AuthServiceAccountToken()
}

func (s *TestClusterSuite) SetupTest() {
	clusterCache = nil
	started = 0
	s.cs = NewClusterService(nil, s.Config)
}

func (s *TestClusterSuite) TearDownTest() {
	if clusterCache != nil {
		clusterCache.stop()
	}
}

func (s *TestClusterSuite) TestClustersFail() {
	_, err := s.cs.Clusters(context.Background())
	assert.EqualError(s.T(), err, "Get http://cluster/api/clusters/: dial tcp: lookup cluster on 127.0.0.53:53: server misbehaving")
}

func (s *TestClusterSuite) TestClusterByURLFail() {
	_, err := s.cs.ClusterByURL(context.Background(), "https://api.starter-us-east-2.openshift.com/")
	assert.EqualError(s.T(), err, "Get http://cluster/api/clusters/: dial tcp: lookup cluster on 127.0.0.53:53: server misbehaving")
}

func (s *TestClusterSuite) TestStart() {
	ctx, _, reqID := tokentestsupport.ContextWithTokenAndRequestID(s.T())

	s.T().Run("start fails if can't get clusters", func(t *testing.T) {
		r, err := recorder.New("../../test/data/cluster/cluster_get_error", recorder.WithMatcher(ClusterRequestMatcher(s.T(), reqID, s.saToken)))
		require.NoError(s.T(), err)
		defer r.Stop()

		err = Start(ctx, s.Config, rest.WithRoundTripper(r.Transport))
		assert.EqualError(s.T(), err, "unable to get clusters from Cluster Management Service. Response status: 500 Internal Server Error. Response body: oopsy woopsy", err.Error())

		assert.Nil(s.T(), clusterCache)
		assert.Equal(s.T(), uint32(0), started)

		_, err = s.cs.Clusters(ctx, rest.WithRoundTripper(r.Transport))
		assert.EqualError(s.T(), err, "unable to get clusters from Cluster Management Service. Response status: 500 Internal Server Error. Response body: oopsy woopsy", err.Error())

		_, err = s.cs.ClusterByURL(ctx, "https://api.starter-us-east-2.openshift.com/", rest.WithRoundTripper(r.Transport))
		assert.EqualError(s.T(), err, "unable to get clusters from Cluster Management Service. Response status: 500 Internal Server Error. Response body: oopsy woopsy", err.Error())
	})

	s.T().Run("start OK", func(t *testing.T) {
		r, err := recorder.New("../../test/data/cluster/cluster_get_ok", recorder.WithMatcher(ClusterRequestMatcher(s.T(), reqID, s.saToken)))
		require.NoError(s.T(), err)
		defer r.Stop()

		// It starts fine if there is no errors
		err = Start(ctx, s.Config, rest.WithRoundTripper(r.Transport))
		require.NoError(s.T(), err)

		assert.NotNil(s.T(), clusterCache)
		assert.Equal(s.T(), uint32(1), started)

		clusters, err := s.cs.Clusters(ctx)
		require.NoError(s.T(), err)
		assert.Equal(s.T(), 2, len(clusters))
		s.assertCluster("https://api.starter-us-east-2.openshift.com/")
		s.assertCluster("https://api.starter-us-east-2.openshift.com")
		s.assertCluster("https://api.starter-us-east-2a.openshift.com/")
		s.assertCluster("https://api.starter-us-east-2a.openshift.com")

		cls, err := s.cs.ClusterByURL(ctx, "https://api.starter-us-east-unknown.openshift.com")
		require.NoError(s.T(), err)
		assert.Nil(s.T(), cls)
	})
}

func (s *TestClusterSuite) assertCluster(apiURL string) {
	cluster, err := s.cs.ClusterByURL(nil, apiURL)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), cluster)

	clusters, err := s.cs.Clusters(nil)
	require.NoError(s.T(), err)
	for _, c := range clusters {
		if c.APIURL == rest.AddTrailingSlashToURL(apiURL) {
			assert.Equal(s.T(), cluster.APIURL, c.APIURL)
			assert.Equal(s.T(), cluster.AuthClientSecret, c.AuthClientSecret)
			assert.Equal(s.T(), cluster.AuthClientDefaultScope, c.AuthClientDefaultScope)
			assert.Equal(s.T(), cluster.AppDNS, c.AppDNS)
			assert.Equal(s.T(), cluster.AuthClientID, c.AuthClientID)
			assert.Equal(s.T(), cluster.CapacityExhausted, c.CapacityExhausted)
			assert.Equal(s.T(), cluster.ConsoleURL, c.ConsoleURL)
			assert.Equal(s.T(), cluster.LoggingURL, c.LoggingURL)
			assert.Equal(s.T(), cluster.MetricsURL, c.MetricsURL)
			assert.Equal(s.T(), cluster.Name, c.Name)
			assert.Equal(s.T(), cluster.ServiceAccountUsername, c.ServiceAccountUsername)
			assert.Equal(s.T(), cluster.ServiceAccountToken, c.ServiceAccountToken)
			assert.Equal(s.T(), cluster.TokenProviderID, c.TokenProviderID)
			return
		}
	}
	assert.Fail(s.T(), "unable to find %s cluster", apiURL)
}

func ClusterRequestMatcher(t *testing.T, reqID, token string) cassette.Matcher {
	return func(httpRequest *http.Request, cassetteRequest cassette.Request) bool {
		authorization := httpRequest.Header.Get("Authorization")
		assert.Equal(t, "Bearer "+token, authorization)

		rID := httpRequest.Header.Get("X-Request-Id")
		assert.Equal(t, reqID, rID)

		assert.Equal(t, cassetteRequest.Method, httpRequest.Method)
		require.NotNil(t, cassetteRequest.Method, httpRequest.URL)
		assert.Equal(t, cassetteRequest.URL, httpRequest.URL.String())

		return true
	}
}
