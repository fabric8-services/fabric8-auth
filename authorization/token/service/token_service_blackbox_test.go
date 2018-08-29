package service_test

import (
	"github.com/fabric8-services/fabric8-auth/authorization/token"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/fabric8-services/fabric8-auth/token/tokencontext"
	"github.com/satori/go.uuid"
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

func (s *tokenServiceBlackboxTest) TestStaleTokenWithUnchangedPrivileges() {
	tm := testtoken.TokenManager

	// Create a user
	u := s.Graph.CreateUser()

	// Create an access token for the user
	at, err := tm.GenerateUserTokenForIdentity(s.Ctx, *u.Identity(), false)
	require.NoError(s.T(), err)

	// Create a new resource type, with scope "mike"
	rt := s.Graph.CreateResourceType()
	rt.AddScope("mike")

	// Create a role with scope mike
	mikeRole := s.Graph.CreateRole(rt)
	mikeRole.AddScope("mike")

	// Create a resource with the new resource type
	res := s.Graph.CreateResource(rt)

	// Assign the mike role to the user for the new resource
	s.Graph.CreateIdentityRole(u, res, mikeRole)

	// Audit the user token for the resource ID
	rptToken, err := s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), u.Identity(), at.AccessToken, res.ResourceID())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rptToken)

	// Parse the signed RPT token
	tokenClaims, err := tm.ParseToken(s.Ctx, *rptToken)
	require.NoError(s.T(), err)

	// There should be one permission in the token
	perms := *tokenClaims.Permissions
	require.Len(s.T(), perms, 1)

	// Extract the token ID from the token
	tokenID, err := uuid.FromString(tokenClaims.Id)
	require.NoError(s.T(), err)

	// "Staleify" the token
	tk, err := s.Application.TokenRepository().Load(s.Ctx, tokenID)
	require.NoError(s.T(), err)

	tk.SetStatus(token.TOKEN_STATUS_STALE, true)
	err = s.Application.TokenRepository().Save(s.Ctx, tk)
	require.NoError(s.T(), err)

	// Audit the RPT token for the same resource ID, it should return nil
	rptToken, err = s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), u.Identity(), *rptToken, res.ResourceID())
	require.NoError(s.T(), err)
	require.Nil(s.T(), rptToken)
}

func (s *tokenServiceBlackboxTest) TestStaleTokenWithChangedPrivileges() {
	tm := testtoken.TokenManager

	// Create a user
	u := s.Graph.CreateUser()

	// Create an access token for the user
	at, err := tm.GenerateUserTokenForIdentity(s.Ctx, *u.Identity(), false)
	require.NoError(s.T(), err)

	// Create a new resource type, with scope "november"
	rt := s.Graph.CreateResourceType()
	rt.AddScope("november")
	rt.AddScope("oscar")

	// Create a role with scope november
	role := s.Graph.CreateRole(rt)
	role.AddScope("november")

	// Create a resource with the new resource type
	res := s.Graph.CreateResource(rt)

	// Assign the role to the user for the new resource
	s.Graph.CreateIdentityRole(u, res, role)

	// Audit the user token for the resource ID
	rptToken, err := s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), u.Identity(), at.AccessToken, res.ResourceID())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rptToken)

	// Parse the signed RPT token
	tokenClaims, err := tm.ParseToken(s.Ctx, *rptToken)
	require.NoError(s.T(), err)

	// There should be one permission in the token
	perms := *tokenClaims.Permissions
	require.Len(s.T(), perms, 1)

	// And it should contain one scope
	require.Len(s.T(), perms[0].Scopes, 1)
	require.Contains(s.T(), perms[0].Scopes, "november")

	// Extract the token ID from the token
	storedTokenID := tokenClaims.Id
	tokenID, err := uuid.FromString(storedTokenID)
	require.NoError(s.T(), err)

	// Now add the "oscar" scope to the role
	role.AddScope("oscar")

	// "Staleify" the token
	tk, err := s.Application.TokenRepository().Load(s.Ctx, tokenID)
	require.NoError(s.T(), err)

	tk.SetStatus(token.TOKEN_STATUS_STALE, true)
	err = s.Application.TokenRepository().Save(s.Ctx, tk)
	require.NoError(s.T(), err)

	// Also mark the privilege cache as stale
	privCache, err := s.Application.PrivilegeCacheRepository().FindForIdentityResource(s.Ctx, u.IdentityID(), res.ResourceID())
	require.NoError(s.T(), err)
	privCache.Stale = true

	// Save the modified privilege cache
	err = s.Application.PrivilegeCacheRepository().Save(s.Ctx, privCache)
	require.NoError(s.T(), err)

	// Audit the RPT token for the same resource ID
	rptToken, err = s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), u.Identity(), *rptToken, res.ResourceID())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rptToken)

	// Parse the signed RPT token
	tokenClaims, err = tm.ParseToken(s.Ctx, *rptToken)
	require.NoError(s.T(), err)

	// It should have a different token ID
	require.NotEqual(s.T(), storedTokenID, tokenClaims.Id)

	// There should still only be one permission
	perms = *tokenClaims.Permissions
	require.Len(s.T(), perms, 1)

	// But it should now contain both scopes
	require.Contains(s.T(), perms[0].Scopes, "november")
	require.Contains(s.T(), perms[0].Scopes, "oscar")
}

func (s *tokenServiceBlackboxTest) TestDeprovisionedToken() {
	tm := testtoken.TokenManager

	// Create a user
	u := s.Graph.CreateUser()

	// Create an access token for the user
	at, err := tm.GenerateUserTokenForIdentity(s.Ctx, *u.Identity(), false)
	require.NoError(s.T(), err)

	// Create a new resource type, with scope "tango"
	rt := s.Graph.CreateResourceType()
	rt.AddScope("tango")

	// Create a role with scope tango
	role := s.Graph.CreateRole(rt)
	role.AddScope("tango")

	// Create a resource with the new resource type
	res := s.Graph.CreateResource(rt)

	// Assign the role to the user for the new resource
	s.Graph.CreateIdentityRole(u, res, role)

	// Audit the user token for the resource ID
	rptToken, err := s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), u.Identity(), at.AccessToken, res.ResourceID())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rptToken)

	// Parse the signed RPT token to get the token ID
	tokenClaims, err := tm.ParseToken(s.Ctx, *rptToken)
	require.NoError(s.T(), err)

	// Extract the token ID from the token
	tokenID, err := uuid.FromString(tokenClaims.Id)
	require.NoError(s.T(), err)

	// Load the token from the repository
	t, err := s.Application.TokenRepository().Load(s.Ctx, tokenID)
	require.NoError(s.T(), err)

	// Mark the token as deprovisioned and save it
	t.SetStatus(token.TOKEN_STATUS_DEPROVISIONED, true)
	err = s.Application.TokenRepository().Save(s.Ctx, t)
	require.NoError(s.T(), err)

	// Audit the RPT token for the same ID
	_, err = s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), u.Identity(), *rptToken, res.ResourceID())
	require.Error(s.T(), err)
	require.IsType(s.T(), err, errors.UnauthorizedError{})
	require.Equal(s.T(), err.(errors.UnauthorizedError).UnauthorizedCode, errors.UNAUTHORIZED_CODE_TOKEN_DEPROVISIONED)
}

func (s *tokenServiceBlackboxTest) TestRevokedToken() {
	tm := testtoken.TokenManager

	// Create a user
	u := s.Graph.CreateUser()

	// Create an access token for the user
	at, err := tm.GenerateUserTokenForIdentity(s.Ctx, *u.Identity(), false)
	require.NoError(s.T(), err)

	// Create a new resource type, with scope "tango"
	rt := s.Graph.CreateResourceType()
	rt.AddScope("uniform")

	// Create a role with the scope
	role := s.Graph.CreateRole(rt)
	role.AddScope("uniform")

	// Create a resource with the new resource type
	res := s.Graph.CreateResource(rt)

	// Assign the role to the user for the new resource
	s.Graph.CreateIdentityRole(u, res, role)

	// Audit the user token for the resource ID
	rptToken, err := s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), u.Identity(), at.AccessToken, res.ResourceID())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rptToken)

	// Parse the signed RPT token to get the token ID
	tokenClaims, err := tm.ParseToken(s.Ctx, *rptToken)
	require.NoError(s.T(), err)

	// Extract the token ID from the token
	tokenID, err := uuid.FromString(tokenClaims.Id)
	require.NoError(s.T(), err)

	// Load the token from the repository
	t, err := s.Application.TokenRepository().Load(s.Ctx, tokenID)
	require.NoError(s.T(), err)

	// Mark the token as revoked and save it
	t.SetStatus(token.TOKEN_STATUS_REVOKED, true)
	err = s.Application.TokenRepository().Save(s.Ctx, t)
	require.NoError(s.T(), err)

	// Audit the RPT token for the same ID
	_, err = s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), u.Identity(), *rptToken, res.ResourceID())
	require.Error(s.T(), err)
	require.IsType(s.T(), err, errors.UnauthorizedError{})
	require.Equal(s.T(), err.(errors.UnauthorizedError).UnauthorizedCode, errors.UNAUTHORIZED_CODE_TOKEN_REVOKED)
}

func (s *tokenServiceBlackboxTest) TestAuditNonExistentResource() {
	tm := testtoken.TokenManager

	// Create a user
	u := s.Graph.CreateUser()

	// Create an access token for the user
	at, err := tm.GenerateUserTokenForIdentity(s.Ctx, *u.Identity(), false)
	require.NoError(s.T(), err)

	// Audit the user token for a non-existent resource ID
	_, err = s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), u.Identity(), at.AccessToken, uuid.NewV4().String())
	require.Error(s.T(), err)
	require.IsType(s.T(), err, errors.BadParameterError{})
}
