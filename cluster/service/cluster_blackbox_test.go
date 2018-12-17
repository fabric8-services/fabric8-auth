package service_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/cluster"
	"github.com/fabric8-services/fabric8-auth/cluster/factory"
	clusterservice "github.com/fabric8-services/fabric8-auth/cluster/service"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-auth/test/recorder"
	tokentestsupport "github.com/fabric8-services/fabric8-auth/test/token"

	"github.com/dnaeon/go-vcr/cassette"
	vcrec "github.com/dnaeon/go-vcr/recorder"
	"github.com/satori/go.uuid"
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
		r, err := recorder.New("../../test/data/cluster/cluster_get_error", recorder.WithDefaultMatcher(reqID, s.saToken))
		require.NoError(t, err)
		defer func() { require.NoError(t, stopRecorder(r)) }()

		_, err = s.Application.ClusterService().Clusters(ctx, rest.WithRoundTripper(r.Transport))
		require.EqualError(t, err, "unable to get clusters from Cluster Management Service. Response status: 500 Internal Server Error. Response body: oopsy woopsy")
	})
	s.T().Run("clusters() fails if can't get clusters", func(t *testing.T) {
		r, err := recorder.New("../../test/data/cluster/cluster_get_error", recorder.WithDefaultMatcher(reqID, s.saToken))
		require.NoError(t, err)
		defer func() { require.NoError(t, stopRecorder(r)) }()

		_, err = s.Application.ClusterService().ClusterByURL(ctx, "https://api.starter-us-east-2.openshift.com/")
		assert.EqualError(t, err, "unable to get clusters from Cluster Management Service. Response status: 500 Internal Server Error. Response body: oopsy woopsy")
	})
}

func (s *ClusterServiceTestSuite) TestRemoveIdentityToClusterLinkOK() {
	ctx, _, reqID := tokentestsupport.ContextWithTokenAndRequestID(s.T())
	identityID := createIdentityIDFromString(s.T())

	s.T().Run("200", func(t *testing.T) {
		clusterURL := "https://cluster.ok/"
		r, err := recorder.New("../../test/data/cluster/unlink_identity_to_cluster", recorder.WithUnLinkIdentityToClusterRequestPayloadMatcher(clusterURL, reqID, s.saToken))
		require.NoError(t, err)
		defer func() { require.NoError(t, stopRecorder(r)) }()

		err = s.Application.ClusterService().RemoveIdentityToClusterLink(ctx, identityID, clusterURL, rest.WithRoundTripper(r.Transport))
		assert.NoError(t, err)
	})
}

func (s *ClusterServiceTestSuite) TestRemoveIdentityToClusterLinkFail() {
	ctx, _, reqID := tokentestsupport.ContextWithTokenAndRequestID(s.T())
	identityID := createIdentityIDFromString(s.T())

	s.T().Run("500", func(t *testing.T) {
		clusterURL := "https://cluster.error/"
		r, err := recorder.New("../../test/data/cluster/unlink_identity_to_cluster", recorder.WithUnLinkIdentityToClusterRequestPayloadMatcher(clusterURL, reqID, s.saToken))
		require.NoError(t, err)
		defer func() { require.NoError(t, stopRecorder(r)) }()

		err = s.Application.ClusterService().RemoveIdentityToClusterLink(ctx, identityID, clusterURL, rest.WithRoundTripper(r.Transport))
		require.EqualError(t, err, "failed to unlink identity to cluster in cluster management service. Response status: 500 Internal Server Error. Response body: oopsy woopsy")
	})

	s.T().Run("400", func(t *testing.T) {
		clusterURL := "https://cluster.bad/"
		r, err := recorder.New("../../test/data/cluster/unlink_identity_to_cluster", recorder.WithUnLinkIdentityToClusterRequestPayloadMatcher(clusterURL, reqID, s.saToken))
		require.NoError(t, err)
		defer func() { require.NoError(t, stopRecorder(r)) }()

		err = s.Application.ClusterService().RemoveIdentityToClusterLink(ctx, identityID, clusterURL, rest.WithRoundTripper(r.Transport))
		require.EqualError(t, err, "failed to unlink identity to cluster in cluster management service. Response status: 400 Bad Request. Response body: invalid identity-id")
	})

	s.T().Run("401", func(t *testing.T) {
		clusterURL := "https://cluster.unauthorized/"
		r, err := recorder.New("../../test/data/cluster/unlink_identity_to_cluster", recorder.WithUnLinkIdentityToClusterRequestPayloadMatcher(clusterURL, reqID, s.saToken))
		require.NoError(t, err)
		defer func() { require.NoError(t, stopRecorder(r)) }()

		err = s.Application.ClusterService().RemoveIdentityToClusterLink(ctx, identityID, clusterURL, rest.WithRoundTripper(r.Transport))
		require.EqualError(t, err, "failed to unlink identity to cluster in cluster management service. Response status: 401 Unauthorized. Response body: unauthorized")
	})

	s.T().Run("404", func(t *testing.T) {
		clusterURL := "https://cluster.notfound/"
		r, err := recorder.New("../../test/data/cluster/unlink_identity_to_cluster", recorder.WithUnLinkIdentityToClusterRequestPayloadMatcher(clusterURL, reqID, s.saToken))
		require.NoError(t, err)
		defer func() { require.NoError(t, stopRecorder(r)) }()

		err = s.Application.ClusterService().RemoveIdentityToClusterLink(ctx, identityID, clusterURL, rest.WithRoundTripper(r.Transport))
		require.EqualError(t, err, "failed to unlink identity to cluster in cluster management service. Response status: 404 Not Found. Response body: not found")
	})
}

func (s *ClusterServiceTestSuite) TestAddIdentityToClusterLinkOK() {
	ctx, _, reqID := tokentestsupport.ContextWithTokenAndRequestID(s.T())
	identityID := createIdentityIDFromString(s.T())

	s.T().Run("200", func(t *testing.T) {
		clusterURL := "https://cluster.ok/"
		r, err := recorder.New("../../test/data/cluster/link_identity_to_cluster", recorder.WithLinkIdentityToClusterRequestPayloadMatcher(clusterURL, reqID, s.saToken))
		require.NoError(t, err)
		defer func() { require.NoError(t, stopRecorder(r)) }()

		err = s.Application.ClusterService().AddIdentityToClusterLink(ctx, identityID, clusterURL, rest.WithRoundTripper(r.Transport))
		assert.NoError(t, err)
	})
}

func (s *ClusterServiceTestSuite) TestAddIdentityToClusterLinkFail() {
	ctx, _, reqID := tokentestsupport.ContextWithTokenAndRequestID(s.T())
	identityID := createIdentityIDFromString(s.T())

	s.T().Run("500", func(t *testing.T) {
		clusterURL := "https://cluster.error/"
		r, err := recorder.New("../../test/data/cluster/link_identity_to_cluster", recorder.WithLinkIdentityToClusterRequestPayloadMatcher(clusterURL, reqID, s.saToken))
		require.NoError(t, err)
		defer func() { require.NoError(t, stopRecorder(r)) }()

		err = s.Application.ClusterService().AddIdentityToClusterLink(ctx, identityID, clusterURL, rest.WithRoundTripper(r.Transport))
		require.EqualError(t, err, "failed to link identity to cluster in cluster management service. Response status: 500 Internal Server Error. Response body: oopsy woopsy")
	})

	s.T().Run("400", func(t *testing.T) {
		clusterURL := "https://cluster.bad/"
		r, err := recorder.New("../../test/data/cluster/link_identity_to_cluster", recorder.WithLinkIdentityToClusterRequestPayloadMatcher(clusterURL, reqID, s.saToken))
		require.NoError(t, err)
		defer func() { require.NoError(t, stopRecorder(r)) }()

		err = s.Application.ClusterService().AddIdentityToClusterLink(ctx, identityID, clusterURL, rest.WithRoundTripper(r.Transport))
		require.EqualError(t, err, "failed to link identity to cluster in cluster management service. Response status: 400 Bad Request. Response body: invalid identity-id")
	})

	s.T().Run("401", func(t *testing.T) {
		clusterURL := "https://cluster.unauthorized/"
		r, err := recorder.New("../../test/data/cluster/link_identity_to_cluster", recorder.WithLinkIdentityToClusterRequestPayloadMatcher(clusterURL, reqID, s.saToken))
		require.NoError(t, err)
		defer func() { require.NoError(t, stopRecorder(r)) }()

		err = s.Application.ClusterService().AddIdentityToClusterLink(ctx, identityID, clusterURL, rest.WithRoundTripper(r.Transport))
		require.EqualError(t, err, "failed to link identity to cluster in cluster management service. Response status: 401 Unauthorized. Response body: unauthorized")
	})
}

func createIdentityIDFromString(t *testing.T) uuid.UUID {
	identityID, err := uuid.FromString("715eab6a-9818-4642-8002-1d0cf8939007")
	require.NoError(t, err)

	return identityID
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
		r, err := recorder.New("../../test/data/cluster/cluster_get_error", recorder.WithDefaultMatcher(reqID, s.saToken))
		require.NoError(t, err)
		defer func() { require.NoError(t, stopRecorder(r)) }()

		started, err := clusterservice.Start(ctx, &dummyFactory{config: s.Configuration, option: rest.WithRoundTripper(r.Transport)}, rest.WithRoundTripper(r.Transport))
		assert.EqualError(t, err, "unable to get clusters from Cluster Management Service. Response status: 500 Internal Server Error. Response body: oopsy woopsy", err.Error())
		assert.False(t, started)

		_, err = s.Application.ClusterService().Clusters(ctx, rest.WithRoundTripper(r.Transport))
		assert.EqualError(t, err, "unable to get clusters from Cluster Management Service. Response status: 500 Internal Server Error. Response body: oopsy woopsy", err.Error())

		_, err = s.Application.ClusterService().ClusterByURL(ctx, "https://api.starter-us-east-2.openshift.com/", rest.WithRoundTripper(r.Transport))
		assert.EqualError(t, err, "unable to get clusters from Cluster Management Service. Response status: 500 Internal Server Error. Response body: oopsy woopsy", err.Error())
	})

	s.T().Run("start OK", func(t *testing.T) {
		r, err := recorder.New("../../test/data/cluster/cluster_get_ok", recorder.WithDefaultMatcher(reqID, s.saToken))
		require.NoError(t, err)
		defer func() { require.NoError(t, stopRecorder(r)) }()

		// It starts fine if there is no errors
		started, err := clusterservice.Start(ctx, &dummyFactory{config: s.Configuration, option: rest.WithRoundTripper(r.Transport)}, rest.WithRoundTripper(r.Transport))
		require.NoError(t, err)
		assert.True(t, started)

		clusters, err := s.Application.ClusterService().Clusters(ctx)
		require.NoError(t, err)
		assert.Equal(t, 2, len(clusters))
		s.assertCluster(t, "https://api.starter-us-east-2.openshift.com/")
		s.assertCluster(t, "https://api.starter-us-east-2.openshift.com")
		s.assertCluster(t, "https://api.starter-us-east-2a.openshift.com/")
		s.assertCluster(t, "https://api.starter-us-east-2a.openshift.com")

		cls, err := s.Application.ClusterService().ClusterByURL(ctx, "https://api.starter-us-east-unknown.openshift.com")
		require.NoError(t, err)
		assert.Nil(t, cls)
	})
}

func (s *ClusterServiceTestSuite) assertCluster(t *testing.T, apiURL string) {
	cluster, err := s.Application.ClusterService().ClusterByURL(nil, apiURL)
	require.NoError(t, err)
	require.NotNil(t, cluster)

	clusters, err := s.Application.ClusterService().Clusters(nil)
	require.NoError(t, err)
	for _, c := range clusters {
		if c.APIURL == rest.AddTrailingSlashToURL(apiURL) {
			assert.Equal(t, cluster.APIURL, c.APIURL)
			assert.Equal(t, cluster.AuthClientSecret, c.AuthClientSecret)
			assert.Equal(t, cluster.AuthClientDefaultScope, c.AuthClientDefaultScope)
			assert.Equal(t, cluster.AppDNS, c.AppDNS)
			assert.Equal(t, cluster.AuthClientID, c.AuthClientID)
			assert.Equal(t, cluster.CapacityExhausted, c.CapacityExhausted)
			assert.Equal(t, cluster.ConsoleURL, c.ConsoleURL)
			assert.Equal(t, cluster.LoggingURL, c.LoggingURL)
			assert.Equal(t, cluster.MetricsURL, c.MetricsURL)
			assert.Equal(t, cluster.Name, c.Name)
			assert.Equal(t, cluster.ServiceAccountUsername, c.ServiceAccountUsername)
			assert.Equal(t, cluster.ServiceAccountToken, c.ServiceAccountToken)
			assert.Equal(t, cluster.TokenProviderID, c.TokenProviderID)
			return
		}
	}
	assert.Fail(s.T(), "unable to find %s cluster", apiURL)
}

func stopRecorder(r *vcrec.Recorder) error {
	err := r.Stop()
	if err != nil {
		return err
	}
	r.SetMatcher(func(httpRequest *http.Request, cassetteRequest cassette.Request) bool {
		return true
	})
	return nil
}
