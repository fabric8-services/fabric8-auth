package service_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/fabric8-services/fabric8-auth/cluster"
	"github.com/fabric8-services/fabric8-auth/cluster/factory"

	"github.com/dnaeon/go-vcr/cassette"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	clusterservice "github.com/fabric8-services/fabric8-auth/cluster/service"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-auth/test/recorder"
	tokentestsupport "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestCluster(t *testing.T) {
	suite.Run(t, &ClusterServiceTestSuite{})
}

type ClusterServiceTestSuite struct {
	gormtestsupport.DBTestSuite
	tm      manager.TokenManager
	saToken string
}

func (s *ClusterServiceTestSuite) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	var err error
	s.tm, err = manager.DefaultManager(s.Configuration)
	require.NoError(s.T(), err)
	s.saToken = s.tm.AuthServiceAccountToken()
}

func (s *ClusterServiceTestSuite) TearDownTest() {
	s.DBTestSuite.TearDownTest()
	s.Application.ClusterService().Stop()
}

func (s *ClusterServiceTestSuite) TestClustersFail() {
	ctx, _, reqID := tokentestsupport.ContextWithTokenAndRequestID(s.T())

	s.T().Run("clusters() fails if can't get clusters", func(t *testing.T) {
		r, err := recorder.New("../../test/data/cluster/cluster_get_error", recorder.WithMatcher(ClusterRequestMatcher(t, reqID, s.saToken)))
		require.NoError(t, err)
		defer func() { require.NoError(s.T(), r.Stop()) }()

		_, err = s.Application.ClusterService().Clusters(ctx, rest.WithRoundTripper(r.Transport))
		require.EqualError(t, err, "unable to get clusters from Cluster Management Service. Response status: 500 Internal Server Error. Response body: oopsy woopsy", err.Error())
	})
	s.T().Run("clusters() fails if can't get clusters", func(t *testing.T) {
		r, err := recorder.New("../../test/data/cluster/cluster_get_error", recorder.WithMatcher(ClusterRequestMatcher(t, reqID, s.saToken)))
		require.NoError(t, err)
		defer func() { require.NoError(s.T(), r.Stop()) }()

		_, err = s.Application.ClusterService().ClusterByURL(ctx, "https://api.starter-us-east-2.openshift.com/")
		assert.EqualError(t, err, "unable to get clusters from Cluster Management Service. Response status: 500 Internal Server Error. Response body: oopsy woopsy", err.Error())
	})
}

type dummyFactory struct {
	config factory.ClusterCacheFactoryConfiguration
	option rest.HTTPClientOption
}

func (f *dummyFactory) NewClusterCache(ctx context.Context, options ...rest.HTTPClientOption) cluster.ClusterCache {
	return cluster.NewCache(f.config, f.option)
}

func (s *ClusterServiceTestSuite) TestStart() {
	ctx, _, reqID := tokentestsupport.ContextWithTokenAndRequestID(s.T())

	s.T().Run("start fails if can't get clusters", func(t *testing.T) {
		r, err := recorder.New("../../test/data/cluster/cluster_get_error", recorder.WithMatcher(ClusterRequestMatcher(t, reqID, s.saToken)))
		require.NoError(t, err)
		defer func() { require.NoError(s.T(), r.Stop()) }()

		started, err := clusterservice.Start(ctx, &dummyFactory{config: s.Configuration, option: rest.WithRoundTripper(r.Transport)}, s.Configuration, rest.WithRoundTripper(r.Transport))
		assert.EqualError(t, err, "unable to get clusters from Cluster Management Service. Response status: 500 Internal Server Error. Response body: oopsy woopsy", err.Error())
		assert.False(t, started)

		_, err = s.Application.ClusterService().Clusters(ctx, rest.WithRoundTripper(r.Transport))
		assert.EqualError(t, err, "unable to get clusters from Cluster Management Service. Response status: 500 Internal Server Error. Response body: oopsy woopsy", err.Error())

		_, err = s.Application.ClusterService().ClusterByURL(ctx, "https://api.starter-us-east-2.openshift.com/", rest.WithRoundTripper(r.Transport))
		assert.EqualError(t, err, "unable to get clusters from Cluster Management Service. Response status: 500 Internal Server Error. Response body: oopsy woopsy", err.Error())
	})

	s.T().Run("start OK", func(t *testing.T) {
		r, err := recorder.New("../../test/data/cluster/cluster_get_ok", recorder.WithMatcher(ClusterRequestMatcher(t, reqID, s.saToken)))
		require.NoError(t, err)
		defer func() { require.NoError(s.T(), r.Stop()) }()

		// It starts fine if there is no errors
		started, err := clusterservice.Start(ctx, &dummyFactory{config: s.Configuration, option: rest.WithRoundTripper(r.Transport)}, s.Configuration, rest.WithRoundTripper(r.Transport))
		require.NoError(t, err)
		assert.True(t, started)

		clusters, err := s.Application.ClusterService().Clusters(ctx)
		require.NoError(t, err)
		assert.Equal(t, 2, len(clusters))
		s.assertCluster("https://api.starter-us-east-2.openshift.com/")
		s.assertCluster("https://api.starter-us-east-2.openshift.com")
		s.assertCluster("https://api.starter-us-east-2a.openshift.com/")
		s.assertCluster("https://api.starter-us-east-2a.openshift.com")

		cls, err := s.Application.ClusterService().ClusterByURL(ctx, "https://api.starter-us-east-unknown.openshift.com")
		require.NoError(t, err)
		assert.Nil(t, cls)
	})
}

func (s *ClusterServiceTestSuite) assertCluster(apiURL string) {
	cluster, err := s.Application.ClusterService().ClusterByURL(nil, apiURL)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), cluster)

	clusters, err := s.Application.ClusterService().Clusters(nil)
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
