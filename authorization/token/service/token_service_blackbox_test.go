package service_test

import (
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/fabric8-services/fabric8-auth/token/tokencontext"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"testing"
)

type tokenServiceBlackboxTest struct {
	gormtestsupport.DBTestSuite
}

func TestRunTokenServiceBlackboxTest(t *testing.T) {
	suite.Run(t, &tokenServiceBlackboxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *tokenServiceBlackboxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
}

func (s *tokenServiceBlackboxTest) TestSimpleAuditAccessToken() {
	tm := testtoken.TokenManager

	// Create a user
	u := s.Graph.CreateUser()

	// Create an access token for the user
	at, err := tm.GenerateUserTokenForIdentity(s.Ctx, *u.Identity(), false)
	require.NoError(s.T(), err)

	// Create a new resource type, with scopes "echo" and "foxtrot"
	rt := s.Graph.CreateResourceType()
	rt.AddScope("echo")
	rt.AddScope("foxtrot")

	// Create a role with scope echo
	echoRole := s.Graph.CreateRole(rt)
	echoRole.AddScope("echo")

	// Create a resource with the new resource type
	r := s.Graph.CreateResource(rt)

	// Assign the echo role to the user for the new resource
	s.Graph.CreateIdentityRole(u, r, echoRole)

	// Audit the user token for the new resource ID
	rptToken, err := s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), u.Identity(), at.AccessToken, r.ResourceID())
	require.NoError(s.T(), err)

	require.NotNil(s.T(), rptToken)

	// Parse the signed RPT token
	tokenClaims, err := tm.ParseToken(s.Ctx, *rptToken)
	require.NoError(s.T(), err)

	// There should be one permission in the token, and it should be for the resource
	require.Len(s.T(), tokenClaims.Permissions, 1)
	perms := *tokenClaims.Permissions
	require.Equal(s.T(), perms[0].ResourceSetID, r.ResourceID())
	// There should be one scope, "echo"
	require.Len(s.T(), perms[0].Scopes, 1)
	require.Contains(s.T(), perms[0].Scopes, "echo")
}
