package service_test

import (
	"context"
	"fmt"
	"testing"

	cheservice "github.com/fabric8-services/fabric8-auth/che/service"
	mockcheservice "github.com/fabric8-services/fabric8-auth/test/generated/che/service"
	testsuite "github.com/fabric8-services/fabric8-common/test/suite"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	uuid "github.com/satori/go.uuid"
	gock "gopkg.in/h2non/gock.v1"
)

func TestChe(t *testing.T) {
	suite.Run(t, &TestCheSuite{})
}

type TestCheSuite struct {
	testsuite.UnitTestSuite 
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
	svc := cheservice.NewCheService(config)

	s.Run("ok", func() {
		// given
		ctx := context.Background()
		identityID:=uuid.NewV4().String()
		gock.New("http://che.test").
			Delete(fmt.Sprintf("api/user/%s", identityID)).
			MatchHeader("Authorization", fmt.Sprintf("Bearer %s", "foo")).
			Reply(200)
		// when
		err := svc.DeleteUser(ctx, identityID)
		// then
		require.NoError(s.T(), err)
	})

}
