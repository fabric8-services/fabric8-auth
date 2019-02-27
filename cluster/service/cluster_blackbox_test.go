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
	tokentestsupport "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gopkg.in/h2non/gock.v1"
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
		defer gock.OffAll()

		gock.New("http://f8cluster").
			Get("api/clusters/auth").
			MatchHeader("Authorization", "Bearer "+s.saToken).
			MatchHeader("X-Request-Id", reqID).
			Reply(500).
			BodyString("oopsy woopsy")

		_, err := s.Application.ClusterService().Clusters(ctx, rest.WithRoundTripper(http.DefaultTransport))
		require.EqualError(t, err, "unable to get clusters from Cluster Management Service. Response status: 500 Internal Server Error. Response body: oopsy woopsy")

	})

	s.T().Run("cluster by url fails if can't get clusters", func(t *testing.T) {
		defer gock.OffAll()
		clusterURL := "https://api.starter-us-east-2.openshift.com/"

		gock.New("http://f8cluster").
			Get("api/clusters/auth").
			MatchHeader("Authorization", "Bearer "+s.saToken).
			MatchHeader("X-Request-Id", reqID).
			Reply(500).
			BodyString("oopsy woopsy")

		_, err := s.Application.ClusterService().ClusterByURL(ctx, clusterURL, rest.WithRoundTripper(http.DefaultTransport))
		assert.EqualError(t, err, "unable to get clusters from Cluster Management Service. Response status: 500 Internal Server Error. Response body: oopsy woopsy")
	})
}

func (s *ClusterServiceTestSuite) TestUnLinkIdentityFromClusterFailOK() {
	ctx, _, reqID := tokentestsupport.ContextWithTokenAndRequestID(s.T())

	s.T().Run("204", func(t *testing.T) {
		defer gock.OffAll()
		clusterURL := "https://cluster.ok/"
		identityID := uuid.NewV4()

		gock.New("http://f8cluster").
			Delete("api/clusters/identities").
			MatchHeader("Authorization", "Bearer "+s.saToken).
			MatchHeader("X-Request-Id", reqID).
			BodyString(WithPayload(identityID, clusterURL)).
			Reply(204)

		err := s.Application.ClusterService().UnlinkIdentityFromCluster(ctx, identityID, clusterURL, rest.WithRoundTripper(http.DefaultTransport))
		assert.NoError(t, err)
	})
}

func (s *ClusterServiceTestSuite) TestUnLinkIdentityFromClusterFail() {
	ctx, _, reqID := tokentestsupport.ContextWithTokenAndRequestID(s.T())

	s.T().Run("500", func(t *testing.T) {
		defer gock.OffAll()
		clusterURL := "https://cluster.error/"
		identityID := uuid.NewV4()

		gock.New("http://f8cluster").
			Delete("api/clusters/identities").
			MatchHeader("Authorization", "Bearer "+s.saToken).
			MatchHeader("X-Request-Id", reqID).
			BodyString(WithPayload(identityID, clusterURL)).
			Reply(500).
			BodyString("oopsy woopsy")

		err := s.Application.ClusterService().UnlinkIdentityFromCluster(ctx, identityID, clusterURL, rest.WithRoundTripper(http.DefaultTransport))
		require.EqualError(t, err, "failed to unlink identity to cluster in cluster management service. Response status: 500 Internal Server Error. Response body: oopsy woopsy")
	})

	s.T().Run("400", func(t *testing.T) {
		defer gock.OffAll()
		clusterURL := "https://cluster.bad/"
		identityID := uuid.NewV4()

		gock.New("http://f8cluster").
			Delete("api/clusters/identities").
			MatchHeader("Authorization", "Bearer "+s.saToken).
			MatchHeader("X-Request-Id", reqID).
			BodyString(WithPayload(identityID, clusterURL)).
			Reply(400).
			BodyString("invalid identity-id")

		err := s.Application.ClusterService().UnlinkIdentityFromCluster(ctx, identityID, clusterURL, rest.WithRoundTripper(http.DefaultTransport))
		require.EqualError(t, err, "failed to unlink identity to cluster in cluster management service. Response status: 400 Bad Request. Response body: invalid identity-id")
	})

	s.T().Run("401", func(t *testing.T) {
		defer gock.OffAll()
		clusterURL := "https://cluster.unauthorized/"
		identityID := uuid.NewV4()

		gock.New("http://f8cluster").
			Delete("api/clusters/identities").
			MatchHeader("Authorization", "Bearer "+s.saToken).
			MatchHeader("X-Request-Id", reqID).
			BodyString(WithPayload(identityID, clusterURL)).
			Reply(401).
			BodyString("unauthorized")

		err := s.Application.ClusterService().UnlinkIdentityFromCluster(ctx, identityID, clusterURL, rest.WithRoundTripper(http.DefaultTransport))
		require.EqualError(t, err, "failed to unlink identity to cluster in cluster management service. Response status: 401 Unauthorized. Response body: unauthorized")
	})

	s.T().Run("404", func(t *testing.T) {
		defer gock.OffAll()
		clusterURL := "https://cluster.notfound/"
		identityID := uuid.NewV4()

		gock.New("http://f8cluster").
			Delete("api/clusters/identities").
			MatchHeader("Authorization", "Bearer "+s.saToken).
			MatchHeader("X-Request-Id", reqID).
			BodyString(WithPayload(identityID, clusterURL)).
			Reply(404).
			BodyString("not found")

		err := s.Application.ClusterService().UnlinkIdentityFromCluster(ctx, identityID, clusterURL, rest.WithRoundTripper(http.DefaultTransport))
		require.EqualError(t, err, "failed to unlink identity to cluster in cluster management service. Response status: 404 Not Found. Response body: not found")
	})
}

func (s *ClusterServiceTestSuite) TestLinkIdentityToClusterOK() {
	ctx, _, reqID := tokentestsupport.ContextWithTokenAndRequestID(s.T())

	s.T().Run("204", func(t *testing.T) {
		defer gock.OffAll()
		clusterURL := "https://cluster.ok/"
		identityID := uuid.NewV4()

		gock.New("http://f8cluster").
			Post("api/clusters/identities").
			MatchHeader("Authorization", "Bearer "+s.saToken).
			MatchHeader("X-Request-Id", reqID).
			BodyString(WithPayload(identityID, clusterURL)).
			Reply(204)

		err := s.Application.ClusterService().LinkIdentityToCluster(ctx, identityID, clusterURL, rest.WithRoundTripper(http.DefaultTransport))
		assert.NoError(t, err)
	})
}

func (s *ClusterServiceTestSuite) TestLinkIdentityToClusterFail() {
	ctx, _, reqID := tokentestsupport.ContextWithTokenAndRequestID(s.T())

	s.T().Run("500", func(t *testing.T) {
		defer gock.OffAll()
		clusterURL := "https://cluster.error/"
		identityID := uuid.NewV4()

		gock.New("http://f8cluster").
			Post("api/clusters/identities").
			MatchHeader("Authorization", "Bearer "+s.saToken).
			MatchHeader("X-Request-Id", reqID).
			BodyString(WithPayload(identityID, clusterURL)).
			Reply(500).
			BodyString("oopsy woopsy")

		err := s.Application.ClusterService().LinkIdentityToCluster(ctx, identityID, clusterURL, rest.WithRoundTripper(http.DefaultTransport))
		require.EqualError(t, err, "failed to link identity to cluster in cluster management service. Response status: 500 Internal Server Error. Response body: oopsy woopsy")
	})

	s.T().Run("400", func(t *testing.T) {
		defer gock.OffAll()
		clusterURL := "https://cluster.bad/"
		identityID := uuid.NewV4()

		gock.New("http://f8cluster").
			Post("api/clusters/identities").
			MatchHeader("Authorization", "Bearer "+s.saToken).
			MatchHeader("X-Request-Id", reqID).
			BodyString(WithPayload(identityID, clusterURL)).
			Reply(400).
			BodyString("invalid identity-id")

		err := s.Application.ClusterService().LinkIdentityToCluster(ctx, identityID, clusterURL, rest.WithRoundTripper(http.DefaultTransport))
		require.EqualError(t, err, "failed to link identity to cluster in cluster management service. Response status: 400 Bad Request. Response body: invalid identity-id")
	})

	s.T().Run("401", func(t *testing.T) {
		defer gock.OffAll()
		clusterURL := "https://cluster.unauthorized/"
		identityID := uuid.NewV4()

		gock.New("http://f8cluster").
			Post("api/clusters/identities").
			MatchHeader("Authorization", "Bearer "+s.saToken).
			MatchHeader("X-Request-Id", reqID).
			BodyString(WithPayload(identityID, clusterURL)).
			Reply(401).
			BodyString("unauthorized")

		err := s.Application.ClusterService().LinkIdentityToCluster(ctx, identityID, clusterURL, rest.WithRoundTripper(http.DefaultTransport))
		require.EqualError(t, err, "failed to link identity to cluster in cluster management service. Response status: 401 Unauthorized. Response body: unauthorized")
	})
}

type dummyFactory struct {
	config factory.ClusterCacheFactoryConfiguration
	option rest.HTTPClientOption
}

func (f *dummyFactory) NewClusterCache(ctx context.Context, options ...rest.HTTPClientOption) cluster.ClusterCache {
	return clusterservice.NewCache(f.config, f.option)
}

func (s *ClusterServiceTestSuite) TestStart() {
	ctx, _, reqID := tokentestsupport.ContextWithTokenAndRequestID(s.T())

	s.T().Run("start fails if can't get clusters", func(t *testing.T) {
		defer gock.OffAll()

		gock.New("http://f8cluster").
			Get("api/clusters/auth").
			Times(3).
			MatchHeader("Authorization", "Bearer "+s.saToken).
			MatchHeader("X-Request-Id", reqID).
			Reply(500).
			BodyString("oopsy woopsy")

		started, err := clusterservice.Start(ctx, &dummyFactory{config: s.Configuration, option: rest.WithRoundTripper(http.DefaultTransport)}, rest.WithRoundTripper(http.DefaultTransport))
		assert.EqualError(t, err, "unable to get clusters from Cluster Management Service. Response status: 500 Internal Server Error. Response body: oopsy woopsy", err.Error())
		assert.False(t, started)

		_, err = s.Application.ClusterService().Clusters(ctx, rest.WithRoundTripper(http.DefaultTransport))
		assert.EqualError(t, err, "unable to get clusters from Cluster Management Service. Response status: 500 Internal Server Error. Response body: oopsy woopsy", err.Error())

		_, err = s.Application.ClusterService().ClusterByURL(ctx, "https://api.starter-us-east-2.openshift.com/", rest.WithRoundTripper(http.DefaultTransport))
		assert.EqualError(t, err, "unable to get clusters from Cluster Management Service. Response status: 500 Internal Server Error. Response body: oopsy woopsy", err.Error())
	})

	s.T().Run("start OK", func(t *testing.T) {
		defer gock.OffAll()
		gock.New("http://f8cluster").
			Get("api/clusters/auth").
			MatchHeader("Authorization", "Bearer "+s.saToken).
			MatchHeader("X-Request-Id", reqID).
			Reply(200).
			BodyString(
				`{
					"data": [
						{
							"api-url": "https://api.starter-us-east-2a.openshift.com/",
							"app-dns": "b542.starter-us-east-2a.openshiftapps.com",
							"auth-client-default-scope": "user:full",
							"auth-client-id": "openshift-io",
							"auth-client-secret": "26c8c584-cbac-427d-8330-8b430b6ec620",
							"capacity-exhausted": false,
							"console-url": "https://console.starter-us-east-2a.openshift.com/console/",
							"logging-url": "https://console.starter-us-east-2a.openshift.com/console/",
							"metrics-url": "https://metrics.starter-us-east-2a.openshift.com/",
							"name": "starter-us-east-2a",
							"service-account-token": "eef1c5b8-f1f4-45dd-beef-7c34be5d9f9b",
							"service-account-username": "devtools-sre",
							"token-provider-id": "dd0ee660-3549-4617-9cab-6e679aab41e9"
						},
						{
							"api-url": "https://api.starter-us-east-2.openshift.com/",
							"app-dns": "a347.starter-us-east-2.openshiftapps.com",
							"auth-client-default-scope": "user:full",
							"auth-client-id": "openshift-io",
							"auth-client-secret": "067da2df-b721-48cd-8e76-ac26e9140218",
							"capacity-exhausted": false,
							"console-url": "https://console.starter-us-east-2.openshift.com/console/",
							"logging-url": "https://console.starter-us-east-2.openshift.com/console/",
							"metrics-url": "https://metrics.starter-us-east-2.openshift.com/",
							"name": "starter-us-east-2",
							"service-account-token": "1d147ba1-2832-4048-b1c5-21ae37377f0d",
							"service-account-username": "devtools-sre",
							"token-provider-id": "33456e01-0ce4-4da2-b94d-daa968412662"
						}
					]
				}`)

		// It starts fine if there is no errors
		started, err := clusterservice.Start(ctx, &dummyFactory{config: s.Configuration, option: rest.WithRoundTripper(http.DefaultTransport)}, rest.WithRoundTripper(http.DefaultTransport))
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

func WithPayload(identityID uuid.UUID, clusterURL string) string {
	return `{ "cluster-url": "` + clusterURL + `", "identity-id": "` + identityID.String() + `" }`
}
