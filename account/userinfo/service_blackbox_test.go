package userinfo_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/account/userinfo"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/goadesign/goa/middleware/security/jwt"
	uuid "github.com/satori/go.uuid"

	_ "github.com/lib/pq"
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
		DB:           s.Application,
	}

}

func (s *serviceBlackBoxTest) TestShowUserInfoOK() {
	goaCtx := context.Background()

	// Create a Sample user and identity
	user, identity, err := getTestUserAndIdentity()

	// Populate your sample user and identities in DB
	s.userInfoProvider.Users.Create(goaCtx, user)
	s.userInfoProvider.Identities.Create(goaCtx, identity)

	// Generate Token
	tokenString, err := testtoken.GenerateToken("a7847bfb-31e9-4bbe-8244-3738151ccd93", "someUserName", testtoken.PrivateKey())
	require.Nil(s.T(), err)

	extracted, err := testtoken.TokenManager.Parse(goaCtx, tokenString)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), extracted)

	// Embed Token in the context
	ctx := jwt.WithJWT(goaCtx, extracted)
	require.NotNil(s.T(), ctx)

	retrievedUser, retrievedIdentity, err := s.userInfoProvider.UserInfo(ctx)
	require.Nil(s.T(), err)

	require.Equal(s.T(), retrievedUser.Email, user.Email)
	require.Equal(s.T(), retrievedUser.FullName, user.FullName)
	require.Equal(s.T(), retrievedIdentity.Username, identity.Username)
	require.Equal(s.T(), retrievedIdentity.ID, identity.ID)

}

func (s *serviceBlackBoxTest) TestShowUserInfoUnauthorized() {
	goaCtx := context.Background()
	_, _, err := s.userInfoProvider.UserInfo(goaCtx)
	require.NotNil(s.T(), err)
	require.Equal(s.T(), err.Error(), fmt.Sprintf("bad token"))

	// Generate Token with an identity that doesn't exist in the database
	sub := uuid.NewV4().String()
	tokenString, err := testtoken.GenerateToken(sub, "someUserName", testtoken.PrivateKey())
	require.Nil(s.T(), err)

	extracted, err := testtoken.TokenManager.Parse(goaCtx, tokenString)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), extracted)

	// Embed Token in the context
	ctx := jwt.WithJWT(goaCtx, extracted)
	require.NotNil(s.T(), ctx)

	_, _, err = s.userInfoProvider.UserInfo(ctx)
	require.NotNil(s.T(), err)
	require.Equal(s.T(), err.Error(), fmt.Sprintf("auth token contains id %s of unknown Identity\n", sub))
}

func getTestUserAndIdentity() (*account.User, *account.Identity, error) {
	userId, err := uuid.FromString("1000a13d-0889-4c00-9a61-b3ce559cbd57")
	if err != nil {
		return nil, nil, err
	}
	usr := account.User{
		ID: userId,
		Lifecycle: gormsupport.Lifecycle{
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		FullName: "TestCurrentAuthorizedOK User",
		ImageURL: "someURL",
		Cluster:  "cluster",
		Email:    "email@domain.com",
	}
	identityId, err := uuid.FromString("a7847bfb-31e9-4bbe-8244-3738151ccd93")
	if err != nil {
		return nil, nil, err
	}
	ident := account.Identity{ID: identityId, Username: "TestUser", ProviderType: account.KeycloakIDP, User: usr, UserID: account.NullUUID{UUID: usr.ID, Valid: true}}

	return &usr, &ident, nil
}
