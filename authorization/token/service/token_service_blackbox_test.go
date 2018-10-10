package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/authorization/token"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testjwt "github.com/fabric8-services/fabric8-auth/test/jwt"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/fabric8-services/fabric8-auth/token/tokencontext"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type tokenServiceBlackboxTest struct {
	gormtestsupport.DBTestSuite
}

func TestTokenServiceBlackbox(t *testing.T) {
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
	rt := s.Graph.CreateResourceType().AddScope("echo")

	// Create a role with scope echo
	echoRole := s.Graph.CreateRole(rt).AddScope("echo")

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
	rt := s.Graph.CreateResourceType().AddScope("foxtrot").AddScope("golf")

	// Create a role with scope foxtrot
	foxtrotRole := s.Graph.CreateRole(rt).AddScope("foxtrot")

	// Create a role with scope golf
	golfRole := s.Graph.CreateRole(rt).AddScope("golf")

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
	rt := s.Graph.CreateResourceType().AddScope("hotel")

	// Create a role with scope hotel
	hotelRole := s.Graph.CreateRole(rt).AddScope("hotel")

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
	rt := s.Graph.CreateResourceType().AddScope("mike")

	// Create a role with scope mike
	mikeRole := s.Graph.CreateRole(rt).AddScope("mike")

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

	// "Staleify" the token
	s.setTokenStatus(s.T(), *rptToken, token.TOKEN_STATUS_STALE)

	// Audit the RPT token for the same resource ID, it should return nil
	rptToken, err = s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), u.Identity(), *rptToken, res.ResourceID())
	require.NoError(s.T(), err)
	require.Nil(s.T(), rptToken)
}

func (s *tokenServiceBlackboxTest) TestStaleTokenWithChangedPrivilegesAfterRoleAddedToUser() {
	// given
	tm := testtoken.TokenManager
	// Create a user
	u := s.Graph.CreateUser()
	// Create an access token for the user
	at, err := tm.GenerateUserTokenForIdentity(s.Ctx, *u.Identity(), false)
	require.NoError(s.T(), err)
	// Create a new resource type, with scopes "november", "oscar" and "papa"
	rt := s.Graph.CreateResourceType().AddScope("november").AddScope("oscar").AddScope("papa")
	// Create a role with scope "november"
	role1 := s.Graph.CreateRole(rt).AddScope("november").AddScope("oscar")
	// Create a resource with the new resource type
	res := s.Graph.CreateResource(rt)
	// Assign the role to the user for the new resource
	s.Graph.CreateIdentityRole(u, res, role1)
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
	require.ElementsMatch(s.T(), perms[0].Scopes, []string{"november", "oscar"})
	// Extract the token ID from the token
	storedTokenID := tokenClaims.Id
	// Now add the second role to the user
	// Create a role with scopes "oscar" and "papa"
	role2 := s.Graph.CreateRole(rt).AddScope("oscar").AddScope("papa")
	// Assign the role to the user for the resource (privileged cache is automatically marked as staled)
	s.Graph.CreateIdentityRole(u, res, role2)
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
	require.ElementsMatch(s.T(), perms[0].Scopes, []string{"november", "oscar", "papa"}) // there should not be duplicate scopes
}

func (s *tokenServiceBlackboxTest) TestStaleTokenWithChangedPrivilegesAfterRoleRemovedFromUser() {
	// given
	tm := testtoken.TokenManager
	// Create a user
	u := s.Graph.CreateUser()
	// Create an access token for the user
	at, err := tm.GenerateUserTokenForIdentity(s.Ctx, *u.Identity(), false)
	require.NoError(s.T(), err)
	// Create a new resource type, with 3 scopes
	rt := s.Graph.CreateResourceType().AddScope("november").AddScope("oscar").AddScope("papa")
	// Create a role with scope "november" and "oscar"
	role1 := s.Graph.CreateRole(rt).AddScope("november").AddScope("oscar")
	// Now add the second role to the user
	// Create a role with scope "oscar" and "papa"
	role2 := s.Graph.CreateRole(rt).AddScope("oscar").AddScope("papa")
	// Create a resource with the new resource type
	res := s.Graph.CreateResource(rt)
	// Assign the 1st role to the user for the new resource
	s.Graph.CreateIdentityRole(u, res, role1)
	// Assign the 2nd role to the user for the resource
	idr := s.Graph.CreateIdentityRole(u, res, role2)
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
	// And it should contain scopes for both roles, without duplicates
	require.ElementsMatch(s.T(), perms[0].Scopes, []string{"november", "oscar", "papa"})
	// Extract the token ID from the token
	storedTokenID := tokenClaims.Id
	// now, let's remove the 2nd role from the user
	idr.Delete()
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
	// But it should now contain only scopes for 1st role
	require.ElementsMatch(s.T(), perms[0].Scopes, []string{"november", "oscar"})
}

func (s *tokenServiceBlackboxTest) TestStaleTokenWithChangedPrivilegesAfterScopeAddedToRole() {
	// given
	tm := testtoken.TokenManager

	// Create a user
	u := s.Graph.CreateUser()

	// Create an access token for the user
	at, err := tm.GenerateUserTokenForIdentity(s.Ctx, *u.Identity(), false)
	require.NoError(s.T(), err)

	// Create a new resource type, with scope "november"
	rt := s.Graph.CreateResourceType().AddScope("november").AddScope("oscar")

	// Create a role with scope november
	role := s.Graph.CreateRole(rt).AddScope("november")

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
	require.ElementsMatch(s.T(), perms[0].Scopes, []string{"november"})

	// Now add the "oscar" scope to the role
	role.AddScope("oscar")

	// "Staleify" the token
	storedTokenID := s.setTokenStatus(s.T(), *rptToken, token.TOKEN_STATUS_STALE, res.ResourceID())
	// also, mark permissions for resource in cache as stale
	s.setPermissionStale(s.T(), u.IdentityID(), res.ResourceID())

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
	require.ElementsMatch(s.T(), perms[0].Scopes, []string{"november", "oscar"})
}

func (s *tokenServiceBlackboxTest) TestDeprovisionedToken() {
	tm := testtoken.TokenManager

	// Create a user
	u := s.Graph.CreateUser()

	// Create an access token for the user
	at, err := tm.GenerateUserTokenForIdentity(s.Ctx, *u.Identity(), false)
	require.NoError(s.T(), err)

	// Create a new resource type, with scope "tango"
	rt := s.Graph.CreateResourceType().AddScope("tango")

	// Create a role with scope tango
	role := s.Graph.CreateRole(rt).AddScope("tango")

	// Create a resource with the new resource type
	res := s.Graph.CreateResource(rt)

	// Assign the role to the user for the new resource
	s.Graph.CreateIdentityRole(u, res, role)

	// Audit the user token for the resource ID
	rptToken, err := s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), u.Identity(), at.AccessToken, res.ResourceID())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rptToken)

	// Mark the token as deprovisioned and save it
	s.setTokenStatus(s.T(), *rptToken, token.TOKEN_STATUS_DEPROVISIONED)

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
	rt := s.Graph.CreateResourceType().AddScope("uniform")

	// Create a role with the scope
	role := s.Graph.CreateRole(rt).AddScope("uniform")

	// Create a resource with the new resource type
	res := s.Graph.CreateResource(rt)

	// Assign the role to the user for the new resource
	s.Graph.CreateIdentityRole(u, res, role)

	// Audit the user token for the resource ID
	rptToken, err := s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), u.Identity(), at.AccessToken, res.ResourceID())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rptToken)
	// Mark the token as revoked and save it
	s.setTokenStatus(s.T(), *rptToken, token.TOKEN_STATUS_REVOKED)

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

func (s *tokenServiceBlackboxTest) TestTokenUpdatedWhenUserAcceptsResourceInvitation() {
	tm := testtoken.TokenManager

	// Create a user
	user := s.Graph.CreateUser()

	// Create an access token for the user
	at, err := tm.GenerateUserTokenForIdentity(s.Ctx, *user.Identity(), false)
	require.NoError(s.T(), err)

	// Create a new resource type with three scopes
	rt := s.Graph.CreateResourceType().AddScope("alpha").AddScope("bravo").AddScope("manage")

	// Create an admin role with manage scope
	adminRole := s.Graph.CreateRole(rt).AddScope("manage")

	// Create an alpha role
	alphaRole := s.Graph.CreateRole(rt, "alpha").AddScope("alpha")

	// Create a bravo role
	bravoRole := s.Graph.CreateRole(rt, "bravo").AddScope("bravo")

	// Create an admin user
	admin := s.Graph.CreateUser()

	// Create a resource
	res := s.Graph.CreateResource(rt)

	// Assign the admin user the admin role for the resource
	s.Graph.CreateIdentityRole(admin, res, adminRole)

	// Assign the user the alpha role for the resource
	s.Graph.CreateIdentityRole(user, res, alphaRole)

	// Audit the user token for the resource ID
	rptToken, err := s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), user.Identity(), at.AccessToken, res.ResourceID())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rptToken)

	// Parse the signed RPT token to obtain the claims
	tokenClaims, err := tm.ParseToken(s.Ctx, *rptToken)
	require.NoError(s.T(), err)

	// There should be one permission in the claims, with the "alpha" scope
	perms := *tokenClaims.Permissions
	require.Len(s.T(), perms, 1)
	require.Contains(s.T(), perms[0].Scopes, "alpha")

	// Issue an invitation for the user to accept the "bravo" role for the resource
	inv := s.Graph.CreateInvitation(user, res, bravoRole)

	// Accept the invitation
	_, _, err = s.Application.InvitationService().Accept(s.Ctx, inv.Invitation().AcceptCode)
	require.NoError(s.T(), err)

	// Audit the user token for same resource ID
	rptToken, err = s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), user.Identity(), *rptToken, res.ResourceID())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rptToken)

	// Parse the signed RPT token to obtain the claims
	tokenClaims, err = tm.ParseToken(s.Ctx, *rptToken)
	require.NoError(s.T(), err)

	// There should still be one permission in the claims, however it should now have both the "alpha" scope and the "bravo" scope
	perms = *tokenClaims.Permissions
	require.Len(s.T(), perms, 1)
	require.ElementsMatch(s.T(), perms[0].Scopes, []string{"alpha", "bravo"})

	// Create another user
	user2 := s.Graph.CreateUser()

	// Create an access token for user2
	at2, err := tm.GenerateUserTokenForIdentity(s.Ctx, *user2.Identity(), false)
	require.NoError(s.T(), err)

	// Issue an invitation for the user to accept the "alpha" role for the resource
	inv = s.Graph.CreateInvitation(user2, res, alphaRole)

	// Accept the invitation
	_, _, err = s.Application.InvitationService().Accept(s.Ctx, inv.Invitation().AcceptCode)
	require.NoError(s.T(), err)

	// Audit user2's token for the same resource ID
	rptToken, err = s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), user2.Identity(), at2.AccessToken, res.ResourceID())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rptToken)

	// Parse the signed RPT token to obtain the claims
	tokenClaims, err = tm.ParseToken(s.Ctx, *rptToken)
	require.NoError(s.T(), err)

	// There should still be one permission in the claims, with "alpha" scope
	perms = *tokenClaims.Permissions
	require.Len(s.T(), perms, 1)
	require.Contains(s.T(), perms[0].Scopes, "alpha")

	// Create a child resource of the resource, with the same type
	res2 := s.Graph.CreateResource(res, rt)

	// Issue an invitation for the user to accept the "bravo" role for res2
	inv = s.Graph.CreateInvitation(user2, res2, bravoRole)

	// Accept the invitation
	_, _, err = s.Application.InvitationService().Accept(s.Ctx, inv.Invitation().AcceptCode)
	require.NoError(s.T(), err)

	// Audit user2's token for the res2's resource ID
	rptToken, err = s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), user2.Identity(), *rptToken, res2.ResourceID())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rptToken)

	// Parse the signed RPT token to obtain the claims
	tokenClaims, err = tm.ParseToken(s.Ctx, *rptToken)
	require.NoError(s.T(), err)

	// There should now be two permissions in the claims
	perms = *tokenClaims.Permissions
	require.Len(s.T(), perms, 2)

	resFound := false
	res2Found := false

	for _, perm := range perms {
		if *perm.ResourceSetID == res.ResourceID() {
			require.Contains(s.T(), perm.Scopes, "alpha")
			resFound = true
		} else if *perm.ResourceSetID == res2.ResourceID() {
			require.ElementsMatch(s.T(), perm.Scopes, []string{"alpha", "bravo"})
			res2Found = true
		}
	}

	require.True(s.T(), resFound, "res not found in permissions claim")
	require.True(s.T(), res2Found, "res2 not found in permissions claim")

	// Create an organization
	org := s.Graph.CreateOrganization()

	// Create a team
	team := s.Graph.CreateTeam()

	// Add the team to the organization
	org.AddMember(team)

	// Create another user, with a new access token
	user3 := s.Graph.CreateUser()
	at3, err := tm.GenerateUserTokenForIdentity(s.Ctx, *user3.Identity(), false)
	require.NoError(s.T(), err)

	// Add user3 to the team
	team.AddMember(user3)

	// Audit user3's token for res2's resource ID
	rptToken, err = s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), user3.Identity(), at3.AccessToken, res2.ResourceID())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rptToken)

	// Parse the signed RPT token to obtain the claims
	tokenClaims, err = tm.ParseToken(s.Ctx, *rptToken)
	require.NoError(s.T(), err)

	// There should be 1 permission, but with no scopes yet
	perms = *tokenClaims.Permissions
	require.Len(s.T(), perms, 1)
	require.Len(s.T(), perms[0].Scopes, 0)

	// Assign the alpha role to the organization for resource res
	err = s.Application.RoleManagementService().ForceAssign(s.Ctx, org.OrganizationID(), "alpha", *res.Resource())
	require.NoError(s.T(), err)

	// Audit user3's token for res2's resource ID again
	rptToken, err = s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), user3.Identity(), *rptToken, res2.ResourceID())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rptToken)

	// Parse the signed RPT token to obtain the claims
	tokenClaims, err = tm.ParseToken(s.Ctx, *rptToken)
	require.NoError(s.T(), err)

	// There should still be 1 permission, but now with the alpha scope
	perms = *tokenClaims.Permissions
	require.Len(s.T(), perms, 1)
	require.Contains(s.T(), perms[0].Scopes, "alpha")

	// Create another resource type, with scope "zulu"
	rt2 := s.Graph.CreateResourceType().AddScope("zulu")

	// Create a role with the zulu scope
	zuluRole := s.Graph.CreateRole(rt2).AddScope("zulu")

	// Create a child resource of res2, with the new resource type
	res3 := s.Graph.CreateResource(res2, rt2)

	// Audit user3's token for res3's resource ID
	rptToken, err = s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), user3.Identity(), *rptToken, res3.ResourceID())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rptToken)

	// Parse the signed RPT token to obtain the claims
	tokenClaims, err = tm.ParseToken(s.Ctx, *rptToken)
	require.NoError(s.T(), err)

	// There should now be 2 permissions, however the permission for res3 should have no scopes
	perms = *tokenClaims.Permissions
	require.Len(s.T(), perms, 2)

	res2Found = false
	res3Found := false

	for _, perm := range perms {
		if *perm.ResourceSetID == res2.ResourceID() {
			require.Contains(s.T(), perm.Scopes, "alpha")
			res2Found = true
		} else if *perm.ResourceSetID == res3.ResourceID() {
			require.Len(s.T(), perm.Scopes, 0)
			res3Found = true
		}
	}

	require.True(s.T(), res2Found)
	require.True(s.T(), res3Found)

	// Create a role mapping, that maps from the bravo role for resource type rt, to zulu role for resource type rt2
	s.Graph.CreateRoleMapping(res, bravoRole, zuluRole)

	// Assign bravo role to the org, for resource res
	err = s.Application.RoleManagementService().ForceAssign(s.Ctx, org.OrganizationID(), "bravo", *res.Resource())
	require.NoError(s.T(), err)

	// Audit user3's token for res3's resource ID
	rptToken, err = s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), user3.Identity(), *rptToken, res3.ResourceID())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rptToken)

	// Parse the signed RPT token to obtain the claims
	tokenClaims, err = tm.ParseToken(s.Ctx, *rptToken)
	require.NoError(s.T(), err)

	// There should still be 2 permissions, however the permission for res3 should now have the zulu scope due to the
	// role mapping
	perms = *tokenClaims.Permissions
	require.Len(s.T(), perms, 2)

	res2Found = false
	res3Found = false

	for _, perm := range perms {
		if *perm.ResourceSetID == res2.ResourceID() {
			require.ElementsMatch(s.T(), perm.Scopes, []string{"alpha", "bravo"})
			res2Found = true
		} else if *perm.ResourceSetID == res3.ResourceID() {
			require.Contains(s.T(), perm.Scopes, "zulu")
			res3Found = true
		}
	}

	require.True(s.T(), res2Found)
	require.True(s.T(), res3Found)

	// Now, remove user user3 from the team
	err = s.Application.Identities().RemoveMember(s.Ctx, team.TeamID(), user3.IdentityID())
	require.NoError(s.T(), err)

	// Audit user3's token for res3's resource ID again
	rptToken, err = s.Application.TokenService().Audit(tokencontext.ContextWithTokenManager(s.Ctx, tm), user3.Identity(), *rptToken, res3.ResourceID())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rptToken)
	// Parse the signed RPT token to obtain the claims
	tokenClaims, err = tm.ParseToken(s.Ctx, *rptToken)
	require.NoError(s.T(), err)
	// There should still be 2 permissions, however neither should have any scopes now
	perms = *tokenClaims.Permissions
	require.Len(s.T(), perms, 2)

	res2Found = false
	res3Found = false

	for _, perm := range perms {
		if *perm.ResourceSetID == res2.ResourceID() {
			require.Len(s.T(), perm.Scopes, 0)
			res2Found = true
		} else if *perm.ResourceSetID == res3.ResourceID() {
			require.Len(s.T(), perm.Scopes, 0)
			res3Found = true
		}
	}

	require.True(s.T(), res2Found)
	require.True(s.T(), res3Found)
}

func (s *tokenServiceBlackboxTest) TestRefresh() {

	tm := testtoken.TokenManager

	s.T().Run("using audit token", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		ctx := testtoken.ContextWithRequest(context.Background())
		// Create a user
		user := g.CreateUser()
		// Create an access token for the user
		at, err := tm.GenerateUserTokenForIdentity(ctx, *user.Identity(), false)
		require.NoError(t, err)
		ctx = tokencontext.ContextWithTokenManager(ctx, tm)
		accessToken, err := tm.Parse(ctx, at.AccessToken)
		require.NoError(t, err)
		// when
		// Refresh the user token
		result, err := s.Application.TokenService().Refresh(ctx, user.Identity(), accessToken.Raw)
		// then the result token should not contain a `permissions` claim
		require.NoError(t, err)
		rptClaims, err := tm.ParseToken(ctx, result)
		require.NoError(t, err)
		assert.Empty(t, rptClaims.Permissions)
	})

	s.T().Run("using RP token", func(t *testing.T) {

		t.Run("containing permissions on 1 resource", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			ctx := tokencontext.ContextWithTokenManager(testtoken.ContextWithRequest(context.Background()), tm)
			// create a user
			user := g.CreateUser()
			// Create an initial access token for the user
			at, err := tm.GenerateUserTokenForIdentity(ctx, *user.Identity(), false)
			require.NoError(t, err)
			atClaims, err := tm.ParseToken(ctx, at.AccessToken)
			require.NoError(t, err)
			// create space
			space := g.CreateSpace().AddAdmin(user)
			time.Sleep(1 * time.Second)
			// create RPT for the space
			rptToken, err := s.Application.TokenService().Audit(ctx, user.Identity(), at.AccessToken, space.SpaceID())
			require.NoError(t, err)
			require.NotNil(t, rptToken)
			// when
			// refresh the user token
			accessToken, err := tm.Parse(ctx, *rptToken)
			require.NoError(t, err)
			result, err := s.Application.TokenService().Refresh(ctx, user.Identity(), accessToken.Raw)
			// then the result token should not contain a `permissions` claim
			require.NoError(t, err)
			rptClaims, err := tm.ParseToken(ctx, result)
			require.NoError(t, err)
			assert.True(t, rptClaims.ExpiresAt > atClaims.ExpiresAt) // verify that the token expiry changed after the refresh
			require.NotNil(t, rptClaims.Permissions)
			permissions := *rptClaims.Permissions
			require.Len(t, permissions, 1)
			assert.Equal(t, *permissions[0].ResourceSetID, space.SpaceID())
			assert.ElementsMatch(t, permissions[0].Scopes, []string{authorization.ManageSpaceScope, authorization.ContributeSpaceScope, authorization.ViewSpaceScope})
		})

		t.Run("containing permissions on 1 resource and staled after change", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			ctx := tokencontext.ContextWithTokenManager(testtoken.ContextWithRequest(context.Background()), tm)
			// create a user
			user := g.CreateUser()
			// Create an initial access token for the user
			at, err := tm.GenerateUserTokenForIdentity(ctx, *user.Identity(), false)
			require.NoError(t, err)
			// create space
			space := g.CreateSpace().AddAdmin(user)
			// create RPT for the 2nd space
			rptToken, err := s.Application.TokenService().Audit(ctx, user.Identity(), at.AccessToken, space.SpaceID())
			require.NoError(t, err)
			// modify permission on 1st space
			space.RemoveAdmin(user).AddViewer(user)
			// when
			// refresh the user token
			accessToken, err := tm.Parse(ctx, *rptToken)
			require.NoError(t, err)
			result, err := s.Application.TokenService().Refresh(ctx, user.Identity(), accessToken.Raw)
			// then the result token should not contain a `permissions` claim
			require.NoError(t, err)
			rptClaims, err := tm.ParseToken(ctx, result)
			require.NoError(t, err)
			require.NotNil(t, rptClaims.Permissions)
			permissions := *rptClaims.Permissions
			require.Len(t, permissions, 1)
			assert.Equal(t, *permissions[0].ResourceSetID, space.SpaceID())
			assert.ElementsMatch(t, permissions[0].Scopes, []string{authorization.ViewSpaceScope})
			t.Logf("new permissions: %v", permissions[0].Scopes)
		})

		t.Run("containing permissions on 2 resources and staled after change", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			ctx := tokencontext.ContextWithTokenManager(testtoken.ContextWithRequest(context.Background()), tm)
			// create a user
			user := g.CreateUser()
			// Create an initial access token for the user
			at, err := tm.GenerateUserTokenForIdentity(ctx, *user.Identity(), false)
			require.NoError(t, err)
			// create space 1
			space1 := g.CreateSpace().AddAdmin(user)
			// create RPT for the 1st space
			rptToken, err := s.Application.TokenService().Audit(ctx, user.Identity(), at.AccessToken, space1.SpaceID())
			require.NoError(t, err)
			// create space 2
			space2 := g.CreateSpace().AddContributor(user)
			// create RPT for the 2nd space
			rptToken, err = s.Application.TokenService().Audit(ctx, user.Identity(), *rptToken, space2.SpaceID())
			require.NoError(t, err)
			// modify permission on 1st space
			space1.RemoveAdmin(user).AddViewer(user)
			// when
			// refresh the user token
			result, err := s.Application.TokenService().Refresh(ctx, user.Identity(), *rptToken)
			// then the result token should not contain a `permissions` claim
			require.NoError(t, err)
			rptClaims, err := tm.ParseToken(ctx, result)
			require.NoError(t, err)
			require.NotNil(t, rptClaims.Permissions)
			permissions := *rptClaims.Permissions
			require.Len(t, permissions, 2)
			assert.Equal(t, *permissions[0].ResourceSetID, space2.SpaceID()) // more recent resource is 1st in the list of permissions
			assert.ElementsMatch(t, permissions[0].Scopes, []string{authorization.ContributeSpaceScope, authorization.ViewSpaceScope})
			assert.Equal(t, *permissions[1].ResourceSetID, space1.SpaceID())
			assert.ElementsMatch(t, permissions[1].Scopes, []string{authorization.ViewSpaceScope})
			t.Logf("new permissions: %v", permissions[1].Scopes)
		})

		t.Run("deprovisioned user", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			ctx := tokencontext.ContextWithTokenManager(testtoken.ContextWithRequest(context.Background()), tm)
			// create a user
			user := g.CreateUser()
			// Create an initial access token for the user
			at, err := tm.GenerateUserTokenForIdentity(ctx, *user.Identity(), false)
			require.NoError(t, err)
			// create space 1
			space := g.CreateSpace().AddAdmin(user)
			// create RPT for the 1st space
			rptToken, err := s.Application.TokenService().Audit(ctx, user.Identity(), at.AccessToken, space.SpaceID())
			require.NoError(t, err)
			// mark user as deprovisionned, ie set the token as deprovisioned and save it
			//s.Application.UserService().DeprovisionUser(ctx, user.Identity().Username) <- no trigger ATM
			s.setTokenStatus(s.T(), *rptToken, token.TOKEN_STATUS_DEPROVISIONED)
			accessToken, err := tm.Parse(ctx, *rptToken)
			require.NoError(t, err)
			// when
			// refresh the user token
			result, err := s.Application.TokenService().Refresh(ctx, user.Identity(), accessToken.Raw)
			// then the result token should not contain a `permissions` claim
			require.Error(t, err)
			assert.IsType(t, errors.UnauthorizedError{}, err)
			assert.Empty(t, result)
		})

		t.Run("revoked token", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			ctx := tokencontext.ContextWithTokenManager(testtoken.ContextWithRequest(context.Background()), tm)
			// create a user
			user := g.CreateUser()
			// Create an initial access token for the user
			at, err := tm.GenerateUserTokenForIdentity(ctx, *user.Identity(), false)
			require.NoError(t, err)
			// create space 1
			space := g.CreateSpace().AddAdmin(user)
			// create RPT for the 1st space
			rptToken, err := s.Application.TokenService().Audit(ctx, user.Identity(), at.AccessToken, space.SpaceID())
			require.NoError(t, err)
			// revoke the token
			tokenClaims, err := tm.ParseToken(ctx, *rptToken)
			require.NoError(t, err)
			tokenID, err := uuid.FromString(tokenClaims.Id)
			require.NoError(s.T(), err)
			tk, err := s.Application.TokenRepository().Load(ctx, tokenID)
			require.NoError(t, err)
			tk.SetStatus(token.TOKEN_STATUS_REVOKED, true)
			err = s.Application.TokenRepository().Save(ctx, tk)
			require.NoError(t, err)
			accessToken, err := tm.Parse(ctx, *rptToken)
			require.NoError(t, err)
			// when
			// refresh the user token
			result, err := s.Application.TokenService().Refresh(ctx, user.Identity(), accessToken.Raw)
			// then the result token should not contain a `permissions` claim
			require.Error(t, err)
			assert.IsType(t, errors.UnauthorizedError{}, err)
			assert.Empty(t, result)
		})

		t.Run("outdated access token (key pair rotated)", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			ctx := tokencontext.ContextWithTokenManager(testtoken.ContextWithRequest(context.Background()), tm)
			// create a user
			user := g.CreateUser()
			// Create an initial access token for the user
			at, err := tm.GenerateUserTokenForIdentity(ctx, *user.Identity(), false)
			require.NoError(t, err)
			tokenClaims, err := tm.ParseToken(ctx, at.AccessToken)
			require.NoError(t, err)
			// create a token for the user...
			tk, err := tm.GenerateUnsignedRPTTokenForIdentity(ctx, tokenClaims, *user.Identity(), nil)
			require.NoError(t, err)
			// ... but sign it with signed by a private key unknown to the tokenManager
			privateKey, err := testjwt.PrivateKey("../../../test/jwt/private_key.pem")
			require.NoError(t, err)
			rptToken, err := tk.SignedString(privateKey)
			require.NoError(t, err)
			// when
			// refresh the user token
			_, err = s.Application.TokenService().Refresh(ctx, user.Identity(), rptToken)
			// then the result token should not contain a `permissions` claim
			require.Error(t, err)
			assert.IsType(t, errors.UnauthorizedError{}, err)
		})

		t.Run("invalid access token", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			ctx := tokencontext.ContextWithTokenManager(testtoken.ContextWithRequest(context.Background()), tm)
			// create a user
			user := g.CreateUser()
			// when
			// refresh the user token
			_, err := s.Application.TokenService().Refresh(ctx, user.Identity(), "foobar")
			// then the result token should not contain a `permissions` claim
			require.Error(t, err)
			assert.IsType(t, errors.UnauthorizedError{}, err)
		})

	})

}

func (s *tokenServiceBlackboxTest) setTokenStatus(t *testing.T, rptToken string, status int, resourceIDs ...string) string {
	// Parse the signed RPT token to get the token ID
	tm := testtoken.TokenManager
	ctx := tokencontext.ContextWithTokenManager(context.Background(), tm)
	tokenClaims, err := tm.ParseToken(ctx, rptToken)
	require.NoError(t, err)
	// Extract the token ID from the token
	tokenID, err := uuid.FromString(tokenClaims.Id)
	require.NoError(s.T(), err)
	// Load the token from the repository
	tk, err := s.Application.TokenRepository().Load(ctx, tokenID)
	require.NoError(t, err)
	tk.SetStatus(status, true)
	err = s.Application.TokenRepository().Save(s.Ctx, tk)
	require.NoError(s.T(), err)
	return tokenClaims.Id
}

func (s *tokenServiceBlackboxTest) setPermissionStale(t *testing.T, identityID uuid.UUID, resourceIDs ...string) {
	for _, resourceID := range resourceIDs {
		// Also mark the privilege cache as stale
		privCache, err := s.Application.PrivilegeCacheRepository().FindForIdentityResource(s.Ctx, identityID, resourceID)
		require.NoError(s.T(), err)
		privCache.Stale = true

		// Save the modified privilege cache
		err = s.Application.PrivilegeCacheRepository().Save(s.Ctx, privCache)
		require.NoError(s.T(), err)
	}
}
