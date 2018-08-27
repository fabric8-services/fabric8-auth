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

	// Create a new resource type, with scope "echo"
	rt := s.Graph.CreateResourceType()
	rt.AddScope("echo")

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
	perms := *tokenClaims.Permissions
	require.Len(s.T(), perms, 1)
	require.Equal(s.T(), *perms[0].ResourceSetID, r.ResourceID())
	// There should be one scope, "echo"
	require.Len(s.T(), perms[0].Scopes, 1)
	require.Contains(s.T(), perms[0].Scopes, "echo")

	// Audit the RPT token for the same resource ID, it should return nil since the privileges haven't changed and the token should not have expired
	rptToken, err = s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), u.Identity(), *rptToken, r.ResourceID())
	require.NoError(s.T(), err)
	require.Nil(s.T(), rptToken)
}

func (s *tokenServiceBlackboxTest) TestRPTTokenReplacedWithAdditionalResource() {
	tm := testtoken.TokenManager

	// Create a user
	u := s.Graph.CreateUser()

	// Create an access token for the user
	at, err := tm.GenerateUserTokenForIdentity(s.Ctx, *u.Identity(), false)
	require.NoError(s.T(), err)

	// Create a new resource type, with scopes "foxtrot" and "golf"
	rt := s.Graph.CreateResourceType()
	rt.AddScope("foxtrot")
	rt.AddScope("golf")

	// Create a role with scope foxtrot
	foxtrotRole := s.Graph.CreateRole(rt)
	foxtrotRole.AddScope("foxtrot")

	// Create a role with scope golf
	golfRole := s.Graph.CreateRole(rt)
	golfRole.AddScope("golf")

	// Create a resource with the new resource type
	r := s.Graph.CreateResource(rt)

	// Assign the foxtrot role to the user for the new resource
	s.Graph.CreateIdentityRole(u, r, foxtrotRole)

	// Audit the user token for the new resource ID
	rptToken, err := s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), u.Identity(), at.AccessToken, r.ResourceID())
	require.NoError(s.T(), err)

	require.NotNil(s.T(), rptToken)

	// Parse the signed RPT token
	tokenClaims, err := tm.ParseToken(s.Ctx, *rptToken)
	require.NoError(s.T(), err)

	// There should be one permission in the token, and it should be for the resource
	perms := *tokenClaims.Permissions
	require.Len(s.T(), perms, 1)
	require.Equal(s.T(), *perms[0].ResourceSetID, r.ResourceID())
	// There should be one scope, "foxtrot"
	require.Len(s.T(), perms[0].Scopes, 1)
	require.Contains(s.T(), perms[0].Scopes, "foxtrot")

	// Create a second resource with the same resource type
	r2 := s.Graph.CreateResource(rt)

	// Assign the golf role to the user for the second resource
	s.Graph.CreateIdentityRole(u, r2, golfRole)

	// Audit the RPT token for the second resource ID
	rptToken, err = s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), u.Identity(), *rptToken, r2.ResourceID())
	require.NoError(s.T(), err)

	require.NotNil(s.T(), rptToken)

	// Parse the signed RPT token
	tokenClaims, err = tm.ParseToken(s.Ctx, *rptToken)
	require.NoError(s.T(), err)

	// There should be two permissions in the token, for both resources
	perms = *tokenClaims.Permissions
	require.Len(s.T(), perms, 2)

	r1Found := false
	r2Found := false

	for _, perm := range perms {
		if *perm.ResourceSetID == r.ResourceID() {
			r1Found = true
			require.Len(s.T(), perm.Scopes, 1)
			require.Contains(s.T(), perm.Scopes, "foxtrot")
		} else if *perm.ResourceSetID == r2.ResourceID() {
			r2Found = true
			require.Len(s.T(), perm.Scopes, 1)
			require.Contains(s.T(), perm.Scopes, "golf")
		}
	}

	require.True(s.T(), r1Found)
	require.True(s.T(), r2Found)
}

func (s *tokenServiceBlackboxTest) TestOldestPermissionRemovedFromMaxSizeToken() {
	tm := testtoken.TokenManager

	// Create a user
	u := s.Graph.CreateUser()

	// Create an access token for the user
	at, err := tm.GenerateUserTokenForIdentity(s.Ctx, *u.Identity(), false)
	require.NoError(s.T(), err)

	// Create a new resource type, with scope "hotel"
	rt := s.Graph.CreateResourceType()
	rt.AddScope("hotel")

	// Create a role with scope hotel
	hotelRole := s.Graph.CreateRole(rt)
	hotelRole.AddScope("hotel")

	// Create a resource with the new resource type
	firstResource := s.Graph.CreateResource(rt)

	// Assign the hotel role to the user for the new resource
	s.Graph.CreateIdentityRole(u, firstResource, hotelRole)

	// Audit the user token for the resource ID
	rptToken, err := s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), u.Identity(), at.AccessToken, firstResource.ResourceID())
	require.NoError(s.T(), err)

	require.NotNil(s.T(), rptToken)

	// Now, let's exceed the maximum size limit for the token
	for i := 0; i < s.Configuration.GetRPTTokenMaxPermissions(); i++ {
		// Create a resource
		res := s.Graph.CreateResource(rt)
		// Assign the hotel role to the user for the resource
		s.Graph.CreateIdentityRole(u, res, hotelRole)

		// Audit the rpt token for the resource ID
		rptToken, err = s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), u.Identity(), *rptToken, res.ResourceID())
		require.NoError(s.T(), err)

		require.NotNil(s.T(), rptToken)
	}

	// Parse the signed RPT token
	tokenClaims, err := tm.ParseToken(s.Ctx, *rptToken)
	require.NoError(s.T(), err)

	// There should be a maximum number of permissions in the token
	perms := *tokenClaims.Permissions
	require.Len(s.T(), perms, s.Configuration.GetRPTTokenMaxPermissions())

	// The first resource should no longer exist in the token
	firstResourceFound := false
	for _, perm := range perms {
		if *perm.ResourceSetID == firstResource.ResourceID() {
			firstResourceFound = true
			break
		}
	}

	require.False(s.T(), firstResourceFound)

	// Confirm that all of the permissions in the token have the hotel scope
	for _, perm := range perms {
		require.Contains(s.T(), perm.Scopes, "hotel")
	}
}
