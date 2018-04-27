package userinfo_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/account/userinfo"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	authtest "github.com/fabric8-services/fabric8-auth/test"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type serviceBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	userInfoProvider userinfo.UserInfoProvider
}

func TestRunServiceBlackBoxTest(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &serviceBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

// SetupSuite overrides the DBTestSuite's function but calls it before doing anything else
// The SetupSuite method will run before the tests in the suite are run.
// It sets up a database connection for all the tests in this suite without polluting global space.
func (s *serviceBlackBoxTest) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	s.userInfoProvider = userinfo.UserInfoProvider{
		TokenManager: testtoken.TokenManager,
		Identities:   account.NewIdentityRepository(s.DB),
		Users:        account.NewUserRepository(s.DB),
		App:          s.Application,
	}
}

func (s *serviceBlackBoxTest) TestShowUserInfoOK() {
	// Create a Sample user and identity
	identity, ctx, err := authtest.EmbedTestIdentityTokenInContext(s.DB, "serviceBlackBoxTestUser")
	require.Nil(s.T(), err)

	retrievedUser, retrievedIdentity, err := s.userInfoProvider.UserInfo(ctx)
	require.Nil(s.T(), err)

	require.Equal(s.T(), retrievedUser.Email, identity.User.Email)
	require.Equal(s.T(), retrievedUser.FullName, identity.User.FullName)
	require.Equal(s.T(), retrievedIdentity.Username, identity.Username)
	require.Equal(s.T(), retrievedIdentity.ID, identity.ID)
}

func (s *serviceBlackBoxTest) TestShowUserInfoUnauthorized() {
	goaCtx := context.Background()
	_, _, err := s.userInfoProvider.UserInfo(goaCtx)
	require.NotNil(s.T(), err)
	require.Equal(s.T(), err.Error(), fmt.Sprintf("bad token"))

	// Generate Token with an identity that doesn't exist in the database
	sub := uuid.Must(uuid.NewV4()).String()
	ctx, err := testtoken.EmbedTokenInContext(sub, uuid.Must(uuid.NewV4()).String())
	require.Nil(s.T(), err)

	_, _, err = s.userInfoProvider.UserInfo(ctx)
	require.NotNil(s.T(), err)
	require.Equal(s.T(), err.Error(), fmt.Sprintf("auth token contains id %s of unknown Identity\n", sub))
}
