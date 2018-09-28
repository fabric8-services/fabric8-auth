package service

import (
	"net/http"
	"testing"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-auth/test/recorder"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"
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
	s.cs = NewClusterService(nil)
}

func (s *TestClusterSuite) TearDownTest() {
	if clusterCache != nil {
		clusterCache.stop()
	}
}

func (s *TestClusterSuite) TestEmptyClusterListIfNotStarted() {
	assert.Empty(s.T(), s.cs.Clusters())
	assert.Nil(s.T(), s.cs.ClusterByURL("https://api.starter-us-east-2.openshift.com/"))
}

func (s *TestClusterSuite) TestStartOK() {
	r, err := recorder.New("../../test/data/cluster/cluster_get_ok", recorder.WithMatcher(ClusterRequestMatcher(s.T(), s.saToken)))
	require.NoError(s.T(), err)
	defer r.Stop()

	err = Start(s.Config, rest.WithRoundTripper(r.Transport))
	require.NoError(s.T(), err)
	clusters := s.cs.Clusters()
	assert.Equal(s.T(), 2, len(clusters))
	s.assertCluster("https://api.starter-us-east-2.openshift.com/")
	s.assertCluster("https://api.starter-us-east-2.openshift.com")
	s.assertCluster("https://api.starter-us-east-2a.openshift.com/")
	s.assertCluster("https://api.starter-us-east-2a.openshift.com")

	assert.Nil(s.T(), s.cs.ClusterByURL("https://api.starter-us-east-unknown.openshift.com"))
}

func (s *TestClusterSuite) TestStartError() {
	r, err := recorder.New("../../test/data/cluster/cluster_get_error", recorder.WithMatcher(ClusterRequestMatcher(s.T(), s.saToken)))
	require.NoError(s.T(), err)
	defer r.Stop()

	err = Start(s.Config, rest.WithRoundTripper(r.Transport))
	require.Error(s.T(), err)
	assert.Equal(s.T(), "unable to get clusters from Cluster Management Service. Response status: 500 Internal Server Error. Response body: oopsy woopsy", err.Error())

	clusters := s.cs.Clusters()
	assert.Equal(s.T(), 0, len(clusters))
	assert.Nil(s.T(), s.cs.ClusterByURL("https://api.starter-us-east-2.openshift.com/"))
}

func (s *TestClusterSuite) assertCluster(apiURL string) {
	cluster := s.cs.ClusterByURL(apiURL)
	require.NotNil(s.T(), cluster)

	clusters := s.cs.Clusters()
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

func ClusterRequestMatcher(t *testing.T, token string) cassette.Matcher {
	return func(httpRequest *http.Request, cassetteRequest cassette.Request) bool {
		authorization := httpRequest.Header.Get("Authorization")
		assert.Equal(t, "Bearer "+token, authorization)

		assert.Equal(t, cassetteRequest.Method, httpRequest.Method)
		require.NotNil(t, cassetteRequest.Method, httpRequest.URL)
		assert.Equal(t, cassetteRequest.URL, httpRequest.URL.String())

		return true
	}
}