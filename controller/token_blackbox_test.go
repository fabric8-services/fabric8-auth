package controller_test

import (
	"context"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/application/service"
	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/authorization/token"
	tokenPkg "github.com/fabric8-services/fabric8-auth/authorization/token"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testjwt "github.com/fabric8-services/fabric8-auth/test/jwt"
	testservice "github.com/fabric8-services/fabric8-auth/test/service"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"

	"github.com/goadesign/goa"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"golang.org/x/oauth2"
)

type TokenControllerTestSuite struct {
	gormtestsupport.DBTestSuite
	testDir string
}

func TestTokenController(t *testing.T) {
	suite.Run(t, &TokenControllerTestSuite{
		DBTestSuite: gormtestsupport.NewDBTestSuite(),
	})
}

func (s *TokenControllerTestSuite) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	s.testDir = filepath.Join("test-files", "token")
}

func (s *TokenControllerTestSuite) UnsecuredController() (*goa.Service, *TokenController) {
	svc := goa.New("Token-Service")
	manager, err := manager.NewTokenManager(s.Configuration)
	require.Nil(s.T(), err)
	return svc, NewTokenController(svc, s.Application, manager, s.Configuration)
}

func (s *TokenControllerTestSuite) SecuredControllerWithNonExistentIdentity() (*goa.Service, *TokenController, account.Identity) {
	svc, ctrl := s.SecuredControllerWithIdentity(testsupport.TestIdentity)
	return svc, ctrl, testsupport.TestIdentity
}

func (s *TokenControllerTestSuite) SecuredController() (*goa.Service, *TokenController, account.Identity) {
	identity, err := testsupport.CreateTestIdentity(s.DB, uuid.NewV4().String(), "KC")
	require.Nil(s.T(), err)
	svc, ctrl := s.SecuredControllerWithIdentity(identity)
	return svc, ctrl, identity
}

func (s *TokenControllerTestSuite) SecuredControllerWithIdentity(identity account.Identity) (*goa.Service, *TokenController) {
	svc := testsupport.ServiceAsUser("Token-Service", identity)
	return svc, NewTokenController(svc, s.Application, testtoken.TokenManager, s.Configuration)
}

func (s *TokenControllerTestSuite) TestPublicKeys() {
	svc, ctrl := s.UnsecuredController()

	s.T().Run("file not found", func(t *testing.T) {
		_, keys := test.KeysTokenOK(s.T(), svc.Context, svc, ctrl, nil)
		s.checkJWK(keys)
	})
	s.T().Run("file not found", func(t *testing.T) {
		jwk := "jwk"
		_, keys := test.KeysTokenOK(s.T(), svc.Context, svc, ctrl, &jwk)
		s.checkJWK(keys)
	})
	s.T().Run("file not found", func(t *testing.T) {
		pem := "pem"
		_, keys := test.KeysTokenOK(s.T(), svc.Context, svc, ctrl, &pem)
		s.checkPEM(keys)
	})
}

func (s *TokenControllerTestSuite) checkPEM(keys *app.PublicKeys) {
	compareWithGolden(s.T(), filepath.Join(s.testDir, "keys", "ok_pem.golden.json"), keys)
}

func (s *TokenControllerTestSuite) checkJWK(keys *app.PublicKeys) {
	compareWithGolden(s.T(), filepath.Join(s.testDir, "keys", "ok_jwk.golden.json"), keys)
}

func (s *TokenControllerTestSuite) checkLoginRequiredHeader(rw http.ResponseWriter) {
	assert.Equal(s.T(), "LOGIN url=http://localhost/api/login, description=\"re-login is required\"", rw.Header().Get("WWW-Authenticate"))
	assert.Contains(s.T(), rw.Header().Get("Access-Control-Expose-Headers"), "WWW-Authenticate")
}

func (s *TokenControllerTestSuite) TestRefreshToken() {

	s.T().Run("using correct refresh token", func(t *testing.T) {

		// given
		svc, ctrl, identity := s.SecuredController()
		tokenSet, err := testtoken.GenerateUserTokenForIdentity(context.Background(), identity, false)
		require.Nil(t, err)
		payload := &app.RefreshToken{
			RefreshToken: &tokenSet.RefreshToken,
		}

		t.Run("without authorization token", func(t *testing.T) {
			// when
			_, authToken := test.RefreshTokenOK(t, svc.Context, svc, ctrl, payload)
			// then
			token := authToken.Token
			require.NotNil(t, token.TokenType)
			assert.Equal(t, "Bearer", *token.TokenType)
			require.NotNil(t, token.AccessToken)
			assert.NotEqual(t, tokenSet.AccessToken, *token.AccessToken) // access_token was renewed
			require.NotNil(t, token.RefreshToken)
			assert.NotEqual(t, tokenSet.RefreshToken, *token.RefreshToken) // // refresh_token was renewed
			expiresIn, ok := token.ExpiresIn.(*int64)
			require.True(t, ok)
			assert.True(t, *expiresIn > 60*59*24*30 && *expiresIn < 60*61*24*30) // The expires_in should be withing a minute range of 30 days.
		})

		t.Run("with valid authorization token", func(t *testing.T) {
			// given
			tokenManager, err := manager.NewTokenManager(s.Configuration)
			require.NoError(s.T(), err)
			tk, err := tokenManager.Parse(s.Ctx, tokenSet.AccessToken)
			require.NoError(s.T(), err)
			ctx := goajwt.WithJWT(svc.Context, tk)
			// when
			_, authToken := test.RefreshTokenOK(t, ctx, svc, ctrl, payload)
			// then
			token := authToken.Token
			require.NotNil(t, token.TokenType)
			assert.Equal(t, "Bearer", *token.TokenType)
			require.NotNil(t, token.AccessToken)
			assert.NotEqual(t, tokenSet.AccessToken, *token.AccessToken) // access_token was renewed
			require.NotNil(t, token.RefreshToken)
			assert.NotEqual(t, tokenSet.RefreshToken, *token.RefreshToken) // refresh_token was renewed
			expiresIn, ok := token.ExpiresIn.(*int64)
			require.True(t, ok)
			assert.True(t, *expiresIn > 60*59*24*30 && *expiresIn < 60*61*24*30) // The expires_in should be withing a minute range of 30 days.
		})

		t.Run("with invalid authorization token", func(t *testing.T) {
			// given a basic token signed with a key that is not loaded in the Token Manager (hence its signature can't be verified/validated)
			utk := jwt.New(jwt.SigningMethodRS256)
			utk.Header["kid"] = "another-key"
			claims := utk.Claims.(jwt.MapClaims)
			claims["jti"] = identity.ID.String() // must match an indentity
			privateKey, err := testjwt.PrivateKey("../test/jwt/private_key.pem")
			require.NoError(t, err)
			stk, err := utk.SignedString(privateKey)
			require.NoError(t, err)
			publicKey, err := testjwt.PublicKey("../test/jwt/public_key.pem")
			require.NoError(t, err)
			tk, err := jwt.Parse(stk, func(token *jwt.Token) (interface{}, error) {
				return publicKey, nil
			})
			require.NoError(t, err)
			ctx := goajwt.WithJWT(svc.Context, tk)
			t.Logf("token raw: %s", tk.Raw)
			// when/then
			test.RefreshTokenUnauthorized(t, ctx, svc, ctrl, payload)
		})

	})

	s.T().Run("failure", func(t *testing.T) {

		t.Run("using nil refresh token", func(t *testing.T) {
			// given
			svc, ctrl, _ := s.SecuredController()
			payload := &app.RefreshToken{}
			// when
			_, err := test.RefreshTokenBadRequest(t, svc.Context, svc, ctrl, payload)
			// then
			assert.NotNil(t, err)
		})

		t.Run("using wrong refresh token", func(t *testing.T) {
			// given
			svc, ctrl, _ := s.SecuredController()
			refreshToken := "WRONG_REFRESH_TOKEN"
			payload := &app.RefreshToken{
				RefreshToken: &refreshToken,
			}
			// when
			rw, _ := test.RefreshTokenUnauthorized(t, svc.Context, svc, ctrl, payload)
			// then
			s.checkLoginRequiredHeader(rw)
		})
	})

}

func (s *TokenControllerTestSuite) TestLinkForNonExistentUserFails() {
	// given
	svc, ctrl, _ := s.SecuredControllerWithNonExistentIdentity()
	redirect := "https://openshift.io"
	// when/then
	test.LinkTokenUnauthorized(s.T(), svc.Context, svc, ctrl, "https://github.com/org/repo", &redirect)
}

func (s *TokenControllerTestSuite) TestLinkNoRedirectNoReferrerFails() {
	// given
	svc, ctrl, _ := s.SecuredController()
	// when/then
	test.LinkTokenBadRequest(s.T(), svc.Context, svc, ctrl, "https://github.com/org/repo", nil)
}

func (s *TokenControllerTestSuite) TestLinkOK() {
	// given
	svc, ctrl, _ := s.SecuredController()
	redirect := "https://openshift.io"
	_, redirectLocation := test.LinkTokenOK(s.T(), svc.Context, svc, ctrl, "https://github.com/org/repo", &redirect)
	require.NotNil(s.T(), redirectLocation)
	require.Equal(s.T(), "providerLocation", redirectLocation.RedirectLocation)
	// when Multiple "for" resources
	_, redirectLocation = test.LinkTokenOK(s.T(), svc.Context, svc, ctrl, "https://github.com/org/repo,"+s.Configuration.GetOpenShiftClientApiUrl(), &redirect)
	// then
	require.NotNil(s.T(), redirectLocation)
	require.Equal(s.T(), "providerLocation", redirectLocation.RedirectLocation)
}

func (s *TokenControllerTestSuite) TestLinkCallbackRedirects() {
	// given
	svc, ctrl, _ := s.SecuredController()
	// when
	response := test.LinkCallbackTokenTemporaryRedirect(s.T(), svc.Context, svc, ctrl, "", "")
	// then
	require.NotNil(s.T(), response)
	location := response.Header()["Location"]
	require.Equal(s.T(), 1, len(location))
	require.Equal(s.T(), "originalLocation", location[0])
}

func (s *TokenControllerTestSuite) TestExchangeFailsWithIncompletePayload() {
	// given
	svc, ctrl, _ := s.SecuredController()
	someRandomString := "someString"
	// when/then
	test.ExchangeTokenBadRequest(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "client_credentials", ClientID: someRandomString})
	test.ExchangeTokenBadRequest(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "authorization_code", ClientID: someRandomString})
	test.ExchangeTokenBadRequest(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "authorization_code", ClientID: someRandomString, RedirectURI: &someRandomString})
	test.ExchangeTokenBadRequest(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "refresh_token", ClientID: someRandomString})
}

func (s *TokenControllerTestSuite) TestExchangeWithWrongCredentialsFails() {
	// given
	svc, ctrl, _ := s.SecuredController()
	someRandomString := "someString"
	witID := "fabric8-wit"
	// when/then
	test.ExchangeTokenUnauthorized(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "client_credentials", ClientSecret: &someRandomString, ClientID: someRandomString})
	test.ExchangeTokenUnauthorized(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "client_credentials", ClientSecret: &someRandomString, ClientID: witID})
}

func (s *TokenControllerTestSuite) TestExchangeWithCorrectCredentialsOK() {
	s.checkServiceAccountCredentials("fabric8-wit", "5dec5fdb-09e3-4453-b73f-5c828832b28e", "witsecret")
	s.checkServiceAccountCredentials("fabric8-tenant", "c211f1bd-17a7-4f8c-9f80-0917d167889d", "tenantsecretOld")
	s.checkServiceAccountCredentials("fabric8-tenant", "c211f1bd-17a7-4f8c-9f80-0917d167889d", "tenantsecretNew")
}

func (s *TokenControllerTestSuite) TestExchangeWithWrongCodeFails() {
	// given
	authProviderService := testservice.NewAuthenticationProviderServiceMock(s.T())
	authProviderService.ExchangeCodeWithProviderFunc = func(ctx context.Context, code string) (*oauth2.Token, error) {
		return nil, errors.NewUnauthorizedError("failed") // return an error when `ExchangeRefreshToken` func is called
	}
	svc, ctrl, _ := s.SecuredController()
	someRandomString := "someString"
	clientID := ctrl.Configuration.GetPublicOAuthClientID()
	code := "INVALID_OAUTH2.0_CODE"
	// when/then
	test.ExchangeTokenUnauthorized(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "authorization_code", RedirectURI: &someRandomString, ClientID: clientID, Code: &code})
	test.ExchangeTokenBadRequest(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "authorization_code", RedirectURI: &someRandomString, ClientID: clientID})
}

func (s *TokenControllerTestSuite) TestExchangeWithWrongClientIDFails() {
	svc, ctrl, _ := s.SecuredController()
	someRandomString := "someString"
	clientID := "someString"
	code := "doesnt_matter"
	refreshToken := "doesnt_matter "
	test.ExchangeTokenUnauthorized(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "authorization_code", RedirectURI: &someRandomString, ClientID: clientID, Code: &code})
	test.ExchangeTokenUnauthorized(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "refresh_token", ClientID: clientID, RefreshToken: &refreshToken})
}

func (s *TokenControllerTestSuite) TestExchangeFailsWithWrongRefreshToken() {
	svc, ctrl, _ := s.SecuredController()
	clientID := ctrl.Configuration.GetPublicOAuthClientID()
	refreshToken := "INVALID_REFRESH_TOKEN"

	rw, _ := test.ExchangeTokenUnauthorized(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "refresh_token", ClientID: clientID, RefreshToken: &refreshToken})
	s.checkLoginRequiredHeader(rw)
}

func (s *TokenControllerTestSuite) TestExchangeWithCorrectCodeOK() {
	// given
	_, expectedAccessToken, expectedRefreshToken := newOAuthMockService(s.T(), testsupport.TestIdentity)
	svc, ctrl, _ := s.SecuredController()
	s.checkAuthorizationCode(svc, ctrl, ctrl.Configuration.GetPublicOAuthClientID(), "SOME_OAUTH2.0_CODE", expectedAccessToken, expectedRefreshToken)
}

func (s *TokenControllerTestSuite) TestExchangeWithCorrectRefreshTokenOK() {
	// given
	_, expectedAccessToken, expectedRefreshToken := newOAuthMockService(s.T(), testsupport.TestIdentity)
	svc, ctrl, _ := s.SecuredController()
	s.checkExchangeWithRefreshToken(svc, ctrl, ctrl.Configuration.GetPublicOAuthClientID(), "SOME_REFRESH_TOKEN", expectedAccessToken, expectedRefreshToken)
}

func (s *TokenControllerTestSuite) TestTokenAuditOK() {
	// given
	// Create a user
	user := s.Graph.CreateUser()
	// Create a new resource type
	rt := s.Graph.CreateResourceType()
	rt.AddScope("lima")
	// Create a new role with the resource type, and with the "lima" scope
	limaRole := s.Graph.CreateRole(rt)
	limaRole.AddScope("lima")
	// Create a resource with the resource type
	res := s.Graph.CreateResource(rt)
	// Assign the role to the user
	s.Graph.CreateIdentityRole(user, res, limaRole)
	// seup controller with mock KeycloakOAuthService behind
	_, accessToken, _ := newOAuthMockService(s.T(), *user.Identity())
	svc, ctrl := s.SecuredControllerWithIdentity(*user.Identity())
	tokenManager, err := manager.NewTokenManager(s.Configuration)
	require.Nil(s.T(), err)
	tk, err := tokenManager.Parse(s.Ctx, accessToken)
	require.NoError(s.T(), err)
	// when
	_, response := test.AuditTokenOK(s.T(), goajwt.WithJWT(svc.Context, tk), svc, ctrl, res.ResourceID())
	// then
	tokenClaims, err := tokenManager.ParseToken(svc.Context, *response.RptToken)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), tokenClaims.Permissions)
	require.Len(s.T(), *tokenClaims.Permissions, 1)
	perms := *tokenClaims.Permissions
	require.Equal(s.T(), res.ResourceID(), *perms[0].ResourceSetID)
	require.Contains(s.T(), perms[0].Scopes, "lima")
}

func (s *TokenControllerTestSuite) TestAuditDeprovisionedToken() {
	// given
	// Create a user
	user := s.Graph.CreateUser()
	// Create a new resource type
	rt := s.Graph.CreateResourceType()
	rt.AddScope("xray")
	// Create a new role with the resource type, and with the "xray" scope
	role := s.Graph.CreateRole(rt)
	role.AddScope("xray")
	// Create a resource with the resource type
	res := s.Graph.CreateResource(rt)
	// Assign the role to the user
	s.Graph.CreateIdentityRole(user, res, role)
	_, accessToken, _ := newOAuthMockService(s.T(), *user.Identity())
	svc, ctrl := s.SecuredControllerWithIdentity(*user.Identity())
	tokenManager, err := manager.NewTokenManager(s.Configuration)
	require.Nil(s.T(), err)
	tk, err := tokenManager.Parse(s.Ctx, accessToken)
	require.NoError(s.T(), err)
	// when
	_, response := test.AuditTokenOK(s.T(), goajwt.WithJWT(svc.Context, tk), svc, ctrl, res.ResourceID())
	// then
	tokenClaims, err := tokenManager.ParseToken(svc.Context, *response.RptToken)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), tokenClaims.Permissions)
	require.Len(s.T(), *tokenClaims.Permissions, 1)
	perms := *tokenClaims.Permissions
	require.Equal(s.T(), res.ResourceID(), *perms[0].ResourceSetID)
	require.Contains(s.T(), perms[0].Scopes, "xray")

	// given: deprovision the token
	tokenID, err := uuid.FromString(tokenClaims.Id)
	require.NoError(s.T(), err)
	t, err := s.Application.TokenRepository().Load(s.Ctx, tokenID)
	require.NoError(s.T(), err)
	t.SetStatus(tokenPkg.TOKEN_STATUS_DEPROVISIONED, true)
	err = s.Application.TokenRepository().Save(s.Ctx, t)
	require.NoError(s.T(), err)
	rptToken, err := tokenManager.Parse(s.Ctx, *response.RptToken)
	require.NoError(s.T(), err)
	// when
	response2, _ := test.AuditTokenUnauthorized(s.T(), goajwt.WithJWT(svc.Context, rptToken), svc, ctrl, res.ResourceID())
	// then
	authHeader := response2.Header().Get("WWW-Authenticate")
	require.True(s.T(), strings.HasPrefix(authHeader, "DEPROVISIONED"))
}

func (s *TokenControllerTestSuite) TestAuditRevokedToken() {
	// given
	// Create a user
	user := s.Graph.CreateUser()
	// Create a new resource type
	rt := s.Graph.CreateResourceType()
	rt.AddScope("victor")
	// Create a new role with the resource type, and with the "victor" scope
	role := s.Graph.CreateRole(rt)
	role.AddScope("victor")
	// Create a resource with the resource type
	res := s.Graph.CreateResource(rt)
	// Assign the role to the user
	s.Graph.CreateIdentityRole(user, res, role)
	_, accessToken, _ := newOAuthMockService(s.T(), *user.Identity())
	svc, ctrl := s.SecuredControllerWithIdentity(*user.Identity())
	tokenManager, err := manager.NewTokenManager(s.Configuration)
	require.Nil(s.T(), err)
	tk, err := tokenManager.Parse(s.Ctx, accessToken)
	require.NoError(s.T(), err)
	// when
	_, response := test.AuditTokenOK(s.T(), goajwt.WithJWT(svc.Context, tk), svc, ctrl, res.ResourceID())
	// then
	tokenClaims, err := tokenManager.ParseToken(svc.Context, *response.RptToken)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), tokenClaims.Permissions)
	require.Len(s.T(), *tokenClaims.Permissions, 1)
	perms := *tokenClaims.Permissions
	require.Equal(s.T(), res.ResourceID(), *perms[0].ResourceSetID)
	require.Contains(s.T(), perms[0].Scopes, "victor")

	// given: deprovision the token
	tokenID, err := uuid.FromString(tokenClaims.Id)
	require.NoError(s.T(), err)
	t, err := s.Application.TokenRepository().Load(s.Ctx, tokenID)
	require.NoError(s.T(), err)
	t.SetStatus(tokenPkg.TOKEN_STATUS_REVOKED, true)
	err = s.Application.TokenRepository().Save(s.Ctx, t)
	require.NoError(s.T(), err)
	rptToken, err := tokenManager.Parse(s.Ctx, *response.RptToken)
	require.NoError(s.T(), err)
	// when
	response2, _ := test.AuditTokenUnauthorized(s.T(), goajwt.WithJWT(svc.Context, rptToken), svc, ctrl, res.ResourceID())
	// then
	authHeader := response2.Header().Get("WWW-Authenticate")
	require.True(s.T(), strings.HasPrefix(authHeader, "LOGIN"))
}

func validateToken(t *testing.T, token *app.AuthToken) {
	assert.NotNil(t, token, "Token data is nil")
	assert.NotEmpty(t, token.Token.AccessToken, "Access token is empty")
	assert.NotEmpty(t, token.Token.RefreshToken, "Refresh token is empty")
	assert.NotEmpty(t, token.Token.TokenType, "Token type is empty")
	assert.NotNil(t, token.Token.ExpiresIn, "Expires-in is nil")
	assert.NotNil(t, token.Token.RefreshExpiresIn, "Refresh-expires-in is nil")
	assert.NotNil(t, token.Token.NotBeforePolicy, "Not-before-policy is nil")
}

func validateUserAndIdentity(t *testing.T, app application.Application) {
	identities, err := app.Identities().Query(account.IdentityWithUser(), account.IdentityFilterByUsername(DevUsername))
	require.NoError(t, err)
	assert.Len(t, identities, 1)

	users, err := app.Users().Query(account.UserFilterByEmail(DevEmail))
	require.NoError(t, err)
	assert.Len(t, users, 1)

	assert.Equal(t, identities[0].User.ID, users[0].ID)
}

func (s *TokenControllerTestSuite) checkServiceAccountCredentials(name string, id string, secret string) {
	svc, ctrl, _ := s.SecuredController()
	_, saToken := test.ExchangeTokenOK(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "client_credentials", ClientSecret: &secret, ClientID: id})
	assert.NotNil(s.T(), saToken.TokenType)
	assert.Equal(s.T(), "Bearer", *saToken.TokenType)
	assert.NotNil(s.T(), saToken.AccessToken)
	claims, err := testtoken.TokenManager.ParseTokenWithMapClaims(context.Background(), *saToken.AccessToken)
	require.Nil(s.T(), err)

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	ctx := goajwt.WithJWT(context.Background(), jwtToken)
	assert.True(s.T(), token.IsServiceAccount(ctx))
	assert.True(s.T(), token.IsSpecificServiceAccount(ctx, name))
}

func (s *TokenControllerTestSuite) checkAuthorizationCode(svc *goa.Service, ctrl *TokenController, name string, code string, expectedAccessToken string, expectedRefreshToken string) {
	_, token := test.ExchangeTokenOK(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "authorization_code", ClientID: s.Configuration.GetPublicOAuthClientID(), Code: &code})

	require.NotNil(s.T(), token)
	require.NotNil(s.T(), token.TokenType)
	require.Equal(s.T(), "Bearer", *token.TokenType)
	require.NotNil(s.T(), token.AccessToken)
	assert.NoError(s.T(), testtoken.EqualAccessTokens(context.Background(), expectedAccessToken, *token.AccessToken))
	require.NotNil(s.T(), token.RefreshToken)
	assert.NoError(s.T(), testtoken.EqualRefreshTokens(context.Background(), expectedRefreshToken, *token.RefreshToken))
	expiresIn, err := strconv.Atoi(*token.ExpiresIn)
	require.Nil(s.T(), err)
	require.True(s.T(), expiresIn > 60*59*24*30 && expiresIn < 60*61*24*30) // The expires_in should be withing a minute range of 30 days.
}

func (s *TokenControllerTestSuite) checkExchangeWithRefreshToken(svc *goa.Service, ctrl *TokenController, name string, refreshToken string, expectedAccessToken, expectedRefreshToken string) {
	_, token := test.ExchangeTokenOK(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "refresh_token", ClientID: s.Configuration.GetPublicOAuthClientID(), RefreshToken: &refreshToken})

	require.NotNil(s.T(), token.TokenType)
	require.Equal(s.T(), "Bearer", *token.TokenType)
	require.NotNil(s.T(), token.AccessToken)
	require.Equal(s.T(), expectedAccessToken, *token.AccessToken)
	require.NotNil(s.T(), token.RefreshToken)
	require.Equal(s.T(), expectedRefreshToken, *token.RefreshToken)
	expiresIn, err := strconv.Atoi(*token.ExpiresIn)
	require.Nil(s.T(), err)
	require.True(s.T(), expiresIn > 60*59*24*30 && expiresIn < 60*61*24*30) // The expires_in should be withing a minute range of 30 days.
}

func (s *TokenControllerTestSuite) TestExchangeWithCorrectCodeButNotApprovedUserOK() {
	// setup the service and ctrl for this specific usecase
	svc := testsupport.ServiceAsUser("Token-Service", testsupport.TestIdentity)
	tokenManager, err := manager.NewTokenManager(s.Configuration)
	require.Nil(s.T(), err)
	oauthService := &NotApprovedOAuthService{}
	ctrl := NewTokenController(svc, s.Application, tokenManager, s.Configuration)

	code := "XYZ"
	_, errResp := test.ExchangeTokenForbidden(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "authorization_code", ClientID: s.Configuration.GetPublicOAuthClientID(), Code: &code})
	require.Equal(s.T(), "user is not authorized to access OpenShift", errResp.Errors[0].Detail)

	oauthService = &NotApprovedOAuthService{}
	oauthService.Scenario = "approved"
	ctrl = NewTokenController(svc, s.Application, tokenManager, s.Configuration)

	code = "XYZ"
	_, returnedToken := test.ExchangeTokenOK(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "authorization_code", ClientID: s.Configuration.GetPublicOAuthClientID(), Code: &code})
	require.NotNil(s.T(), returnedToken.AccessToken)
}

type DummyLinkService struct {
}

func (s *DummyLinkService) ProviderLocation(ctx context.Context, req *goa.RequestData, identityID string, forResource string, redirectURL string) (string, error) {
	return "providerLocation", nil
}

func (s *DummyLinkService) Callback(ctx context.Context, req *goa.RequestData, state string, code string) (string, error) {
	return "originalLocation", nil
}

func newOAuthMockService(t *testing.T, identity account.Identity) (service.AuthenticationProviderService, string, string) {
	authProviderService := testservice.NewAuthenticationProviderServiceMock(t)
	tokenSet, err := testtoken.GenerateUserTokenForIdentity(context.Background(), identity, false)
	require.Nil(t, err)
	authProviderService.ExchangeCodeWithProviderFunc = func(ctx context.Context, code string) (*oauth2.Token, error) {
		var thirtyDays, nbf int64
		thirtyDays = 60 * 60 * 24 * 30
		token := &oauth2.Token{
			TokenType:    "Bearer",
			AccessToken:  tokenSet.AccessToken,
			RefreshToken: tokenSet.RefreshToken,
			Expiry:       time.Unix(time.Now().Unix()+thirtyDays, 0),
		}
		extra := make(map[string]interface{})
		extra["expires_in"] = thirtyDays
		extra["refresh_expires_in"] = thirtyDays
		extra["not_before_policy"] = nbf
		token = token.WithExtra(extra)
		return token, nil
	}
	authProviderService.CreateOrUpdateIdentityAndUserFunc = func(ctx context.Context, referrerURL *url.URL, keycloakToken *oauth2.Token) (*string, *oauth2.Token, error) {
		var thirtyDays, nbf int64
		thirtyDays = 60 * 60 * 24 * 30
		token := &oauth2.Token{
			TokenType:    "Bearer",
			Expiry:       time.Unix(time.Now().Unix()+thirtyDays, 0),
			AccessToken:  keycloakToken.AccessToken,
			RefreshToken: keycloakToken.RefreshToken,
		}

		extra := make(map[string]interface{})
		extra["expires_in"] = thirtyDays
		extra["refresh_expires_in"] = thirtyDays
		extra["not_before_policy"] = nbf
		token = token.WithExtra(extra)

		return nil, token, nil
	}
	return authProviderService, tokenSet.AccessToken, tokenSet.RefreshToken
}

type NotApprovedOAuthService struct {
	service.AuthenticationProviderService
	Scenario string
}

func (s *NotApprovedOAuthService) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	bearer := "Bearer"
	token := &oauth2.Token{
		TokenType:    bearer,
		AccessToken:  "sometoken",
		RefreshToken: "sometoken",
	}
	return token, nil
}

func (s *NotApprovedOAuthService) CreateOrUpdateIdentityAndUser(ctx context.Context, referrerURL *url.URL, keycloakToken *oauth2.Token) (*string, *oauth2.Token, error) {

	/* This mocked method simulates the contract
	where redir url is always returned, but token is returned when there is not error
	*/

	redirURLNotApproved := "http://not-approved"
	redirURLApproved := "http://approved"
	bearer := "Bearer"
	token := &oauth2.Token{
		TokenType:    bearer,
		AccessToken:  "sometoken",
		RefreshToken: "sometoken",
	}
	if s.Scenario == "approved" {
		return &redirURLApproved, token, nil
	}
	return &redirURLNotApproved, nil, nil
}
