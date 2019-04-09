package service_test

import (
	"fmt"
	//"github.com/gophercloud/gophercloud/openstack/compute/v2/images"
	"testing"

	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	mockcheservice "github.com/fabric8-services/fabric8-auth/test/generated/che/service"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"gopkg.in/h2non/gock.v1"
)

func TestChe(t *testing.T) {
	suite.Run(t, &TestCheSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

type TestCheSuite struct {
	gormtestsupport.DBTestSuite
}

func (s *TestCheSuite) TestDeleteUser() {
	// ctx, _, reqID := testtoken.ContextWithTokenAndRequestID(s.T())
	// ctx = manager.ContextWithTokenManager(ctx, testtoken.TokenManager)

	// saToken := testtoken.TokenManager.AuthServiceAccountToken()
	defer gock.OffAll()
	gock.Observe(gock.DumpRequest)
	config := mockcheservice.NewConfigurationMock(s.T())
	config.GetCheServiceURLFunc = func() string {
		return "http://che.test"
	}

	s.Run("ok", func() {
		// given
		identity := s.Graph.CreateIdentity().Identity()

		gock.New("http://che.test").
			Delete(fmt.Sprintf("api/user/%s", identity.ID)).
			MatchHeader("Authorization", fmt.Sprintf("Bearer %s", "foo")).
			Reply(200)
		// when
		err := s.Application.CheService().DeleteUser(s.Ctx, *identity)
		// then
		require.NoError(s.T(), err)
	})

}
