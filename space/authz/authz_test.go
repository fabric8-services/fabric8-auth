package authz_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/fabric8-services/fabric8-auth/space/authz"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"

	"github.com/dgrijalva/jwt-go"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const (
	testSpaceID = "a2c706fa-7421-452c-8a34-91016e5a4eab"
)

var (
	scopes = []string{"read:test", "admin:test"}
)

func TestAuthz(t *testing.T) {
	resource.Require(t, resource.Remote)
	suite.Run(t, new(TestAuthzSuite))
}

type TestAuthzSuite struct {
	testsuite.RemoteTestSuite
	authzService        *authz.KeycloakAuthzService
	entitlementEndpoint string
	test1Token          string
	test2Token          string
}

func (s *TestAuthzSuite) SetupSuite() {
	s.RemoteTestSuite.SetupSuite()
	var err error
	if s.Config.IsKeycloakTestsDisabled() {
		s.T().Skip("Skipping Keycloak tests")
	}
	s.authzService = authz.NewAuthzService(s.Config)
	s.entitlementEndpoint, err = s.Config.GetKeycloakEndpointEntitlement(nil)
	if err != nil {
		panic(fmt.Errorf("failed to get endpoint from configuration: %s", err.Error()))
	}
	tokenEndpoint, err := s.Config.GetKeycloakEndpointToken(nil)
	if err != nil {
		panic(fmt.Errorf("failed to get endpoint from configuration: %s", err.Error()))
	}

	token, err := controller.GenerateUserToken(context.Background(), tokenEndpoint, s.Config, s.Config.GetKeycloakTestUserName(), s.Config.GetKeycloakTestUserSecret())
	if err != nil {
		panic(fmt.Errorf("failed to generate token: %s", err.Error()))
	}
	if token.Token.AccessToken == nil {
		panic("failed to generate token")
	}

	s.test1Token = *token.Token.AccessToken

	token, err = controller.GenerateUserToken(context.Background(), tokenEndpoint, s.Config, s.Config.GetKeycloakTestUser2Name(), s.Config.GetKeycloakTestUser2Secret())
	if err != nil {
		panic(fmt.Errorf("failed to generate token: %s", err.Error()))
	}
	if token.Token.AccessToken == nil {
		panic("failed to generate token")
	}

	s.test2Token = *token.Token.AccessToken
}

func (s *TestAuthzSuite) TestFailsIfNoTokenInContext() {
	ctx := context.Background()
	_, err := s.authzService.Authorize(ctx, s.entitlementEndpoint, testSpaceID)
	require.NotNil(s.T(), err)
	require.IsType(s.T(), errors.UnauthorizedError{}, err)
}

func (s *TestAuthzSuite) TestUserAmongSpaceCollaboratorsOK() {
	ok := s.checkPermissions(s.test1Token, testSpaceID)
	require.True(s.T(), ok)
}

func (s *TestAuthzSuite) TestUserIsNotAmongSpaceCollaboratorsFails() {
	ok := s.checkPermissions(s.test2Token, testSpaceID)
	require.False(s.T(), ok)
}

func (s *TestAuthzSuite) checkPermissions(token string, spaceID string) bool {
	tk := jwt.New(jwt.SigningMethodRS256)
	tk.Raw = token
	ctx := goajwt.WithJWT(context.Background(), tk)
	authzService := authz.NewAuthzService(s.Config)
	ok, err := authzService.Authorize(ctx, s.entitlementEndpoint, spaceID)
	require.Nil(s.T(), err)
	return ok
}
