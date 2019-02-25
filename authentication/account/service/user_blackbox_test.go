package service_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/fabric8-services/fabric8-auth/authentication/provider"

	"github.com/fabric8-services/fabric8-auth/test/graph"

	"github.com/fabric8-services/fabric8-auth/authorization/token"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/fabric8-services/fabric8-common/gocksupport"

	"github.com/jinzhu/gorm"
	errs "github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	gock "gopkg.in/h2non/gock.v1"
)

type userServiceBlackboxTestSuite struct {
	gormtestsupport.DBTestSuite
}

func TestUserService(t *testing.T) {
	suite.Run(t, &userServiceBlackboxTestSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *userServiceBlackboxTestSuite) TestDeprovisionUnknownUserFails() {
}

func (s *userServiceBlackboxTestSuite) TestDeprovision() {

	s.T().Run("ok", func(t *testing.T) {
		userToDeprovision := s.Graph.CreateUser()
		userToStayIntact := s.Graph.CreateUser()

		identity, err := s.Application.UserService().DeprovisionUser(s.Ctx, userToDeprovision.Identity().Username)
		require.NoError(t, err)
		assert.True(t, identity.User.Deprovisioned)
		assert.Equal(t, userToDeprovision.User().ID, identity.User.ID)
		assert.Equal(t, userToDeprovision.IdentityID(), identity.ID)

		loadedUser := s.Graph.LoadUser(userToDeprovision.IdentityID())
		assert.True(t, loadedUser.User().Deprovisioned)
		userToDeprovision.Identity().User.Deprovisioned = true
		testsupport.AssertIdentityEqual(t, userToDeprovision.Identity(), loadedUser.Identity())

		loadedUser = s.Graph.LoadUser(userToStayIntact.IdentityID())
		assert.Equal(t, false, loadedUser.User().Deprovisioned)
		testsupport.AssertIdentityEqual(t, userToStayIntact.Identity(), loadedUser.Identity())
	})

	s.T().Run("fail", func(t *testing.T) {

		s.T().Run("unknown user", func(t *testing.T) {
			// given
			username := uuid.NewV4().String()
			// when
			_, err := s.Application.UserService().DeprovisionUser(s.Ctx, username)
			// then
			testsupport.AssertError(t, err, errors.NotFoundError{}, "user identity with username '%s' not found", username)

		})
	})
}

func (s *userServiceBlackboxTestSuite) TestDeactivate() {

	// given
	ctx, _, reqID := testtoken.ContextWithTokenAndRequestID(s.T())
	saToken := testtoken.TokenManager.AuthServiceAccountToken()

	s.T().Run("ok", func(t *testing.T) {
		// given 2 users with tokens
		userToDeactivate := s.Graph.CreateUser()
		token1 := s.Graph.CreateToken(userToDeactivate)
		token2 := s.Graph.CreateToken(userToDeactivate)
		githubTokenToRemove := s.Graph.CreateExternalToken(userToDeactivate, provider.GitHubProviderID)
		openshiftTokenToRemove := s.Graph.CreateExternalToken(userToDeactivate, "33456e01-0ce4-4da2-b94d-daa968412662") // ID of the OpenShift cluster returned by gock on behalf of the cluster service
		userToStayIntact := s.Graph.CreateUser()
		token3 := s.Graph.CreateToken(userToStayIntact)
		token4 := s.Graph.CreateToken(userToStayIntact)
		githubTokenToKeep := s.Graph.CreateExternalToken(userToStayIntact, provider.GitHubProviderAlias)
		openshiftTokenToKeep := s.Graph.CreateExternalToken(userToStayIntact, "02f2eee5-d01a-4119-9893-292a7d39b49e") // ID of the OpenShift cluster returned by gock on behalf of the cluster service

		defer gock.OffAll()
		// call to Cluster Service
		gock.New("http://f8cluster").
			Get("/api/clusters/auth").
			// MatchHeader("Authorization", "Bearer "+saToken).
			// MatchHeader("X-Request-Id", reqID).
			Reply(200).
			BodyString(
				fmt.Sprintf(`{
					"data": [
						{
							"token-provider-id": "33456e01-0ce4-4da2-b94d-daa968412662",
							"api-url": "%s",
							"app-dns": "a347.foo.openshiftapps.com",
							"auth-client-default-scope": "user:full",
							"auth-client-id": "openshift-io",
							"auth-client-secret": "067da2df-b721-48cd-8e76-ac26e9140218",
							"capacity-exhausted": false,
							"console-url": "https://console.foo.openshift.com/console/",
							"logging-url": "https://console.foo.openshift.com/console/",
							"metrics-url": "https://metrics.foo.openshift.com/",
							"name": "foo",
							"service-account-token": "1d147ba1-2832-4048-b1c5-21ae37377f0d",
							"service-account-username": "devtools-sre"
						},
						{
							"token-provider-id": "02f2eee5-d01a-4119-9893-292a7d39b49e",
							"api-url": "%s",
							"app-dns": "a347.foo.openshiftapps.com",
							"auth-client-default-scope": "user:full",
							"auth-client-id": "openshift-io",
							"auth-client-secret": "90ceb4c9-842a-4a82-8f1b-e2fd2e0117fe",
							"capacity-exhausted": false,
							"console-url": "https://console.foo.openshift.com/console/",
							"logging-url": "https://console.foo.openshift.com/console/",
							"metrics-url": "https://metrics.foo.openshift.com/",
							"name": "foo",
							"service-account-token": "1d147ba1-2832-4048-b1c5-21ae37377f0d",
							"service-account-username": "devtools-sre"
						}
					]
				}`, userToDeactivate.User().Cluster, userToStayIntact.User().Cluster))
		// call to WIT Service
		witCallsCounter := 0
		gock.Observe(gock.DumpRequest)
		gock.New("http://localhost:8080").
			Delete(fmt.Sprintf("/api/users/username/%s", userToDeactivate.IdentityID().String())).
			MatchHeader("Authorization", "Bearer "+saToken).
			MatchHeader("X-Request-Id", reqID).
			SetMatcher(gocksupport.SpyOnCalls(&witCallsCounter)).
			Reply(200)
		// call to Tenant Service
		tenantCallsCounter := 0
		gock.New("http://localhost:8090").
			Delete(fmt.Sprintf("/api/tenants/%s", userToDeactivate.IdentityID().String())).
			MatchHeader("Authorization", "Bearer "+saToken).
			MatchHeader("X-Request-Id", reqID).
			SetMatcher(gocksupport.SpyOnCalls(&tenantCallsCounter)).
			Reply(204)

		// when
		identity, err := s.Application.UserService().DeactivateUser(ctx, userToDeactivate.Identity().Username)
		// then
		require.NoError(t, err)
		assert.False(t, identity.User.Active)        // user is inactive...
		assert.False(t, identity.User.Deprovisioned) // ... but user NOT deprovisionned
		assert.Equal(t, userToDeactivate.User().ID, identity.User.ID)
		assert.Equal(t, userToDeactivate.IdentityID(), identity.ID)
		// verify that user's fields were obfuscated and that the record was soft-deleted
		loadedUser := s.Graph.LoadUser(userToDeactivate.IdentityID(), graph.Unscoped())
		require.NotNil(t, loadedUser)
		testsupport.AssertIdentityObfuscated(t, userToDeactivate.Identity(), loadedUser.Identity())
		testsupport.AssertIdentitySoftDeleted(t, loadedUser.Identity())
		// also, verify that user's tokens were revoked
		for _, tID := range []uuid.UUID{token1.TokenID(), token2.TokenID()} {
			tok := s.Graph.LoadToken(tID)
			require.NotNil(t, tok)
			assert.Equal(t, tok.Token().Status, token.TOKEN_STATUS_REVOKED)
		}
		// also, verify that WIT and tenant services were called
		assert.Equal(t, 1, witCallsCounter)
		assert.Equal(t, 1, tenantCallsCounter)
		// also, verify that the external accounts where unlinked
		_, err = s.Application.ExternalTokens().Load(ctx, githubTokenToRemove.ID())
		require.Error(t, err)
		_, err = s.Application.ExternalTokens().Load(ctx, openshiftTokenToRemove.ID())
		require.Error(t, err)
		// lastly, verify that everything belonging to the user to keep intact remainded as-is
		loadedUser = s.Graph.LoadUser(userToStayIntact.IdentityID())
		assert.True(t, loadedUser.User().Active)
		testsupport.AssertIdentityEqual(t, userToStayIntact.Identity(), loadedUser.Identity())
		for _, tID := range []uuid.UUID{token3.TokenID(), token4.TokenID()} {
			tok := s.Graph.LoadToken(tID)
			require.NotNil(t, tok)
			assert.True(t, tok.Token().Valid())
		}
		_, err = s.Application.ExternalTokens().Load(ctx, githubTokenToKeep.ID())
		require.NoError(t, err)
		_, err = s.Application.ExternalTokens().Load(ctx, openshiftTokenToKeep.ID())
		require.NoError(t, err)

	})

	s.T().Run("not found", func(t *testing.T) {
		// when
		_, err := s.Application.UserService().DeactivateUser(s.Ctx, "unknown")
		// then
		testsupport.AssertError(t, err, errors.NotFoundError{}, "user identity with username 'unknown' not found")
	})
}

func (s *userServiceBlackboxTestSuite) TestHardDeleteUser() {

	s.T().Run("ok", func(t *testing.T) {
		user := s.Graph.CreateUser()

		err := s.Application.UserService().HardDeleteUser(s.Ctx, *user.Identity())
		require.NoError(t, err)

		includeSoftDeletes := func(db *gorm.DB) *gorm.DB {
			return db.Unscoped()
		}

		userID := user.User().ID
		loadedUser, err := s.Application.Users().Load(s.Ctx, userID, includeSoftDeletes)
		require.EqualError(s.T(), err, fmt.Sprintf("user with id '%s' not found", userID))
		require.Nil(t, loadedUser)

		loadedUser, err = s.Application.Users().Load(s.Ctx, userID)
		require.EqualError(t, err, fmt.Sprintf("user with id '%s' not found", userID))
		require.Nil(t, loadedUser)

		identityID := user.IdentityID()
		identity, err := s.Application.Identities().Load(s.Ctx, identityID, includeSoftDeletes)
		require.EqualError(t, err, fmt.Sprintf("identity with id '%s' not found", identityID))
		require.Nil(t, identity)

		identity, err = s.Application.Identities().Load(s.Ctx, identityID)
		require.EqualError(t, err, fmt.Sprintf("identity with id '%s' not found", identityID))
		require.Nil(t, identity)
	})
}

func (s *userServiceBlackboxTestSuite) TestResetDeprovision() {
	userToResetDeprovision := s.Graph.CreateUser()
	userToStayIntact := s.Graph.CreateUser()

	identity, err := s.Application.UserService().DeprovisionUser(s.Ctx, userToResetDeprovision.Identity().Username)
	require.NoError(s.T(), err)
	assert.True(s.T(), identity.User.Deprovisioned)

	identityToStayIntact, err := s.Application.UserService().DeprovisionUser(s.Ctx, userToStayIntact.Identity().Username)
	require.NoError(s.T(), err)
	assert.True(s.T(), identityToStayIntact.User.Deprovisioned)

	err = s.Application.UserService().ResetDeprovision(s.Ctx, identity.User)
	require.NoError(s.T(), err)

	loadedUser := s.Graph.LoadUser(userToResetDeprovision.IdentityID())
	assert.False(s.T(), loadedUser.User().Deprovisioned)

	loadedUser = s.Graph.LoadUser(userToStayIntact.IdentityID())
	assert.True(s.T(), loadedUser.User().Deprovisioned)
}

func (s *userServiceBlackboxTestSuite) TestIdentityByUsernameAndEmail() {
	s.T().Run("found", func(t *testing.T) {
		user := s.Graph.CreateUser()
		s.Graph.CreateUser() // noise

		identity, err := s.Application.UserService().IdentityByUsernameAndEmail(s.Ctx, user.Identity().Username, user.User().Email)
		require.NoError(t, err)
		loadedUser := s.Graph.LoadUser(user.IdentityID())
		testsupport.AssertIdentityEqual(t, identity, loadedUser.Identity())
	})

	s.T().Run("unknown", func(t *testing.T) {
		user := s.Graph.CreateUser()
		s.T().Run("unknown email", func(t *testing.T) {
			identity, err := s.Application.UserService().IdentityByUsernameAndEmail(s.Ctx, user.Identity().Username, uuid.NewV4().String())
			require.NoError(t, err)
			assert.Nil(t, identity)
		})
		s.T().Run("unknown username", func(t *testing.T) {
			identity, err := s.Application.UserService().IdentityByUsernameAndEmail(s.Ctx, uuid.NewV4().String(), user.User().Email)
			require.NoError(t, err)
			assert.Nil(t, identity)
		})
		s.T().Run("unknown username and email", func(t *testing.T) {
			identity, err := s.Application.UserService().IdentityByUsernameAndEmail(s.Ctx, uuid.NewV4().String(), uuid.NewV4().String())
			require.NoError(t, err)
			assert.Nil(t, identity)
		})
	})
}

func (s *userServiceBlackboxTestSuite) TestShowUserInfoOK() {

	s.T().Run("ok", func(t *testing.T) {
		// given a sample user and identity
		identity, ctx, err := testsupport.EmbedTestIdentityTokenInContext(s.DB, "UserServiceBlackBoxTest-User")
		require.Nil(t, err)
		// when
		retrievedUser, retrievedIdentity, err := s.Application.UserService().UserInfo(ctx, identity.ID)
		require.Nil(t, err)
		// then
		assert.Equal(t, identity.User.Email, retrievedUser.Email)
		assert.Equal(t, identity.User.FullName, retrievedUser.FullName)
		assert.Equal(t, identity.Username, retrievedIdentity.Username)
		assert.Equal(t, identity.ID, retrievedIdentity.ID)
		assert.Equal(t, identity.ID, retrievedIdentity.ID)

	})

	s.T().Run("not found", func(t *testing.T) {
		// given a random ID
		id := uuid.NewV4()
		// when
		_, _, err := s.Application.UserService().UserInfo(context.Background(), id)
		// then
		require.Error(t, err)
		assert.IsType(t, errors.UnauthorizedError{}, errs.Cause(err))
	})

}
