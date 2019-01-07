package service

import (
	"github.com/fabric8-services/fabric8-auth/rest"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"
	tokentestsupport "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gopkg.in/h2non/gock.v1"
	"net/http"
	"strconv"
	"testing"

	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
)

func TestClusterService(t *testing.T) {
	suite.Run(t, &ClusterServiceTestSuite{})
}

type ClusterServiceTestSuite struct {
	testsuite.UnitTestSuite
	cs      *clusterService
	tm      manager.TokenManager
	saToken string
}

func (s *ClusterServiceTestSuite) SetupSuite() {
	s.UnitTestSuite.SetupSuite()

	var err error
	s.tm, err = manager.DefaultManager(s.Config)
	require.NoError(s.T(), err)

	s.saToken = s.tm.AuthServiceAccountToken()
	s.cs = NewClusterService(nil, s.Config).(*clusterService)
}

func (s *ClusterServiceTestSuite) TestLinkAllExistingIdentityToCluster() {
	ctx, _, reqID := tokentestsupport.ContextWithTokenAndRequestID(s.T())

	s.T().Run("ok", func(t *testing.T) {
		defer gock.OffAll()
		identitiesWithClusterURL := make(map[uuid.UUID]string)
		for i := 0; i < 5; i++ {
			identityID := uuid.NewV4()
			clusterURL := "https://cluster" + strconv.Itoa(i) + "/"
			identitiesWithClusterURL[identityID] = clusterURL
			gock.New("http://f8cluster").
				Post("api/clusters/identities").
				MatchHeader("X-Request-Id", reqID).
				MatchHeader("Authorization", "Bearer "+s.saToken).
				BodyString(WithPayload(identityID, clusterURL)).
				Reply(204)
		}

		errs, e := s.cs.linkIdentitiesToCluster(ctx, identitiesWithClusterURL, rest.WithRoundTripper(http.DefaultTransport))
		err, ok := <-errs

		//then
		assert.NoError(t, e)
		assert.False(t, ok)
		assert.NoError(t, err)
	})

	s.T().Run("fail", func(t *testing.T) {
		defer gock.OffAll()
		identitiesWithClusterURL := make(map[uuid.UUID]string)
		for i := 0; i < 2; i++ {
			identityID := uuid.NewV4()
			clusterURL := "https://cluster" + strconv.Itoa(i) + "/"
			identitiesWithClusterURL[identityID] = clusterURL
			gock.New("http://f8cluster").
				Post("api/clusters/identities").
				MatchHeader("Authorization", "Bearer "+s.saToken).
				MatchHeader("X-Request-Id", reqID).
				BodyString(WithPayload(identityID, clusterURL)).
				Reply(500).
				BodyString("something went wrong")
		}

		errs, e := s.cs.linkIdentitiesToCluster(ctx, identitiesWithClusterURL, rest.WithRoundTripper(http.DefaultTransport))
		for i := 0; i < 2; i++ {
			err, ok := <-errs

			//then
			assert.NoError(t, e)
			assert.True(t, ok)
			require.Error(t, err)
			assert.Equal(t, "failed to link identity to cluster in cluster management service. Response status: 500 Internal Server Error. Response body: something went wrong", err.Error())
		}
	})
}

func WithPayload(identityID uuid.UUID, clusterURL string) string {
	return `{ "cluster-url": "` + clusterURL + `", "identity-id": "` + identityID.String() + `" }`
}
