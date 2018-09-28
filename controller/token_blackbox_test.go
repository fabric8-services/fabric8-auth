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
	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	tokenPkg "github.com/fabric8-services/fabric8-auth/authorization/token"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/login"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testlogin "github.com/fabric8-services/fabric8-auth/test/login"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/fabric8-services/fabric8-auth/token/oauth"

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
	manager, err := token.NewManager(s.Configuration)
	require.Nil(s.T(), err)
	loginService := testlogin.NewKeycloakOAuthServiceMock(s.T())
	return svc, NewTokenController(svc, s.Application, loginService, nil, nil, manager, s.Configuration)
}

func (s *TokenControllerTestSuite) SecuredControllerWithNonExistentIdentity(loginService login.KeycloakOAuthService) (*goa.Service, *TokenController) {
	return s.SecuredControllerWithIdentity(testsupport.TestIdentity, loginService)
}

func (s *TokenControllerTestSuite) SecuredController(loginService login.KeycloakOAuthService) (*goa.Service, *TokenController) {
	identity, err := testsupport.CreateTestIdentity(s.DB, uuid.NewV4().String(), "KC")
	require.Nil(s.T(), err)
	return s.SecuredControllerWithIdentity(identity, loginService)
}

func (s *TokenControllerTestSuite) SecuredControllerWithIdentity(identity account.Identity, loginService login.KeycloakOAuthService) (*goa.Service, *TokenController) {
	newTestKeycloakOAuthProvider(s.Application)
	svc := testsupport.ServiceAsUser("Token-Service", identity)
	linkService := &DummyLinkService{}
	return svc, NewTokenController(svc, s.Application, loginService, linkService, nil, testtoken.TokenManager, s.Configuration)
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
		loginService := testlogin.NewKeycloakOAuthServiceMock(t)
		svc, ctrl := s.SecuredController(loginService)
		tokenSet, err := testtoken.GenerateUserTokenForIdentity(context.Background(), testsupport.TestIdentity, false)
		require.Nil(t, err)
		payload := &app.RefreshToken{
			RefreshToken: &tokenSet.RefreshToken,
		}

		t.Run("without authorization token", func(t *testing.T) {
			// given
			loginService.ExchangeRefreshTokenFunc = func(ctx context.Context, accessToken, refreshToken string, serviceConfig login.Configuration) (*token.TokenSet, error) {
				var thirtyDays int64
				thirtyDays = 60 * 60 * 24 * 30
				bearer := "Bearer"
				return &token.TokenSet{
					TokenType:    &bearer,
					AccessToken:  &tokenSet.AccessToken,
					RefreshToken: &tokenSet.RefreshToken,
					ExpiresIn:    &thirtyDays,
				}, nil
			}
			// when
			_, authToken := test.RefreshTokenOK(t, svc.Context, svc, ctrl, payload)
			// then
			token := authToken.Token
			require.NotNil(t, token.TokenType)
			require.Equal(t, "Bearer", *token.TokenType)
			require.NotNil(t, token.AccessToken)
			assert.Equal(t, tokenSet.AccessToken, *token.AccessToken)
			require.NotNil(t, token.RefreshToken)
			assert.Equal(t, tokenSet.RefreshToken, *token.RefreshToken)
			expiresIn, ok := token.ExpiresIn.(*int64)
			require.True(t, ok)
			require.True(t, *expiresIn > 60*59*24*30 && *expiresIn < 60*61*24*30) // The expires_in should be withing a minute range of 30 days.
		})

		t.Run("with valid authorization token", func(t *testing.T) {
			// given
			loginService.ExchangeRefreshTokenFunc = func(ctx context.Context, accessToken, refreshToken string, serviceConfig login.Configuration) (*token.TokenSet, error) {
				var thirtyDays int64
				thirtyDays = 60 * 60 * 24 * 30
				bearer := "Bearer"
				// configure the mock behaviour to return an refresh token only
				return &token.TokenSet{
					TokenType:    &bearer,
					AccessToken:  &tokenSet.AccessToken,
					RefreshToken: &refreshToken,
					ExpiresIn:    &thirtyDays,
				}, nil
			}
			manager, err := token.NewManager(s.Configuration)
			tk, err := manager.Parse(s.Ctx, tokenSet.AccessToken)
			require.NoError(s.T(), err)
			ctx := goajwt.WithJWT(svc.Context, tk)
			// when
			_, authToken := test.RefreshTokenOK(t, ctx, svc, ctrl, payload)
			// then
			token := authToken.Token
			require.NotNil(t, token.TokenType)
			require.Equal(t, "Bearer", *token.TokenType)
			require.NotNil(t, token.AccessToken)
			require.Equal(t, tokenSet.AccessToken, *token.AccessToken)
			require.NotNil(t, token.RefreshToken)
			require.Equal(t, tokenSet.RefreshToken, *token.RefreshToken)
			expiresIn, ok := token.ExpiresIn.(*int64)
			require.True(t, ok)
			require.True(t, *expiresIn > 60*59*24*30 && *expiresIn < 60*61*24*30) // The expires_in should be withing a minute range of 30 days.
		})

		t.Run("with invalid authorization token", func(t *testing.T) {
			// given
			loginService.ExchangeRefreshTokenFunc = func(ctx context.Context, accessToken, refreshToken string, serviceConfig login.Configuration) (*token.TokenSet, error) {
				return nil, errors.NewUnauthorizedError("failed") // return an error when `ExchangeRefreshToken` func is called
			}
			manager, err := token.NewManager(s.Configuration)
			tk, err := manager.Parse(s.Ctx, tokenSet.AccessToken)
			require.NoError(s.T(), err)
			ctx := goajwt.WithJWT(svc.Context, tk)
			// when/then
			test.RefreshTokenUnauthorized(t, ctx, svc, ctrl, payload)
		})

	})

	s.T().Run("failure", func(t *testing.T) {

		t.Run("using nil refresh token", func(t *testing.T) {
			// given
			loginService, _, _ := newKeycloakOAuthMockService(t, testsupport.TestIdentity)
			svc, ctrl := s.SecuredController(loginService)
			payload := &app.RefreshToken{}
			// when
			_, err := test.RefreshTokenBadRequest(t, svc.Context, svc, ctrl, payload)
			// then
			assert.NotNil(t, err)
		})

		t.Run("using wrong refresh token", func(t *testing.T) {
			// given
			loginService := testlogin.NewKeycloakOAuthServiceMock(t)
			loginService.ExchangeRefreshTokenFunc = func(ctx context.Context, accessToken, refreshToken string, serviceConfig login.Configuration) (*token.TokenSet, error) {
				return nil, errors.NewUnauthorizedError("failed") // return an error when `ExchangeRefreshToken` func is called
			}
			svc, ctrl := s.SecuredController(loginService)
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
	loginService, _, _ := newKeycloakOAuthMockService(s.T(), testsupport.TestIdentity)
	svc, ctrl := s.SecuredControllerWithNonExistentIdentity(loginService)
	redirect := "https://openshift.io"
	// when/then
	test.LinkTokenUnauthorized(s.T(), svc.Context, svc, ctrl, "https://github.com/org/repo", &redirect)
}

func (s *TokenControllerTestSuite) TestLinkNoRedirectNoReferrerFails() {
	// given
	loginService, _, _ := newKeycloakOAuthMockService(s.T(), testsupport.TestIdentity)
	svc, ctrl := s.SecuredController(loginService)
	// when/then
	test.LinkTokenBadRequest(s.T(), svc.Context, svc, ctrl, "https://github.com/org/repo", nil)
}

func (s *TokenControllerTestSuite) TestLinkOK() {
	// given
	loginService, _, _ := newKeycloakOAuthMockService(s.T(), testsupport.TestIdentity)
	svc, ctrl := s.SecuredController(loginService)
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
	loginService, _, _ := newKeycloakOAuthMockService(s.T(), testsupport.TestIdentity)
	svc, ctrl := s.SecuredController(loginService)
	// when
	response := test.CallbackTokenTemporaryRedirect(s.T(), svc.Context, svc, ctrl, "", "")
	// then
	require.NotNil(s.T(), response)
	location := response.Header()["Location"]
	require.Equal(s.T(), 1, len(location))
	require.Equal(s.T(), "originalLocation", location[0])
}

func (s *TokenControllerTestSuite) TestExchangeFailsWithIncompletePayload() {
	// given
	loginService, _, _ := newKeycloakOAuthMockService(s.T(), testsupport.TestIdentity)
	svc, ctrl := s.SecuredController(loginService)
	someRandomString := "someString"
	// when/then
	test.ExchangeTokenBadRequest(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "client_credentials", ClientID: someRandomString})
	test.ExchangeTokenBadRequest(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "authorization_code", ClientID: someRandomString})
	test.ExchangeTokenBadRequest(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "authorization_code", ClientID: someRandomString, RedirectURI: &someRandomString})
	test.ExchangeTokenBadRequest(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "refresh_token", ClientID: someRandomString})
}

func (s *TokenControllerTestSuite) TestExchangeWithWrongCredentialsFails() {
	// given
	loginService, _, _ := newKeycloakOAuthMockService(s.T(), testsupport.TestIdentity)
	svc, ctrl := s.SecuredController(loginService)
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
	loginService := testlogin.NewKeycloakOAuthServiceMock(s.T())
	loginService.ExchangeFunc = func(ctx context.Context, code string, config oauth.OauthConfig) (*oauth2.Token, error) {
		return nil, errors.NewUnauthorizedError("failed") // return an error when `ExchangeRefreshToken` func is called
	}
	svc, ctrl := s.SecuredController(loginService)
	someRandomString := "someString"
	clientID := ctrl.Configuration.GetPublicOauthClientID()
	code := "INVALID_OAUTH2.0_CODE"
	// when/then
	test.ExchangeTokenUnauthorized(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "authorization_code", RedirectURI: &someRandomString, ClientID: clientID, Code: &code})
	test.ExchangeTokenBadRequest(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "authorization_code", RedirectURI: &someRandomString, ClientID: clientID})
}

func (s *TokenControllerTestSuite) TestExchangeWithWrongClientIDFails() {
	// given
	loginService, _, _ := newKeycloakOAuthMockService(s.T(), testsupport.TestIdentity)
	svc, ctrl := s.SecuredController(loginService)
	someRandomString := "someString"
	clientID := "someString"
	code := "doesnt_matter"
	refreshToken := "doesnt_matter "
	test.ExchangeTokenUnauthorized(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "authorization_code", RedirectURI: &someRandomString, ClientID: clientID, Code: &code})
	test.ExchangeTokenUnauthorized(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "refresh_token", ClientID: clientID, RefreshToken: &refreshToken})
}

func (s *TokenControllerTestSuite) TestExchangeFailsWithWrongRefreshToken() {
	// given
	loginService := testlogin.NewKeycloakOAuthServiceMock(s.T())
	loginService.ExchangeRefreshTokenFunc = func(ctx context.Context, accessToken, refreshToken string, serviceConfig login.Configuration) (*token.TokenSet, error) {
		return nil, errors.NewUnauthorizedError("failed") // return an error when `ExchangeRefreshToken` func is called
	}
	svc, ctrl := s.SecuredController(loginService)
	clientID := ctrl.Configuration.GetPublicOauthClientID()
	refreshToken := "INVALID_REFRESH_TOKEN"

	rw, _ := test.ExchangeTokenUnauthorized(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "refresh_token", ClientID: clientID, RefreshToken: &refreshToken})
	s.checkLoginRequiredHeader(rw)
}

func (s *TokenControllerTestSuite) TestExchangeWithCorrectCodeOK() {
	// given
	loginService, expectedAccessToken, expectedRefreshToken := newKeycloakOAuthMockService(s.T(), testsupport.TestIdentity)
	svc, ctrl := s.SecuredController(loginService)
	s.checkAuthorizationCode(svc, ctrl, ctrl.Configuration.GetPublicOauthClientID(), "SOME_OAUTH2.0_CODE", expectedAccessToken, expectedRefreshToken)
}

func (s *TokenControllerTestSuite) TestExchangeWithCorrectRefreshTokenOK() {
	// given
	loginService, expectedAccessToken, expectedRefreshToken := newKeycloakOAuthMockService(s.T(), testsupport.TestIdentity)
	svc, ctrl := s.SecuredController(loginService)
	s.checkExchangeWithRefreshToken(svc, ctrl, ctrl.Configuration.GetPublicOauthClientID(), "SOME_REFRESH_TOKEN", expectedAccessToken, expectedRefreshToken)
}

func (s *TokenControllerTestSuite) TestGenerateOK() {
	// given
	loginService, _, _ := newKeycloakOAuthMockService(s.T(), testsupport.TestIdentity)
	svc, ctrl := s.SecuredController(loginService)
	_, result := test.GenerateTokenOK(s.T(), svc.Context, svc, ctrl)
	require.Len(s.T(), result, 1)
	validateToken(s.T(), result[0])
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
	loginService, accessToken, _ := newKeycloakOAuthMockService(s.T(), *user.Identity())
	svc, ctrl := s.SecuredControllerWithIdentity(*user.Identity(), loginService)
	manager, err := token.NewManager(s.Configuration)
	require.Nil(s.T(), err)
	tk, err := manager.Parse(s.Ctx, accessToken)
	require.NoError(s.T(), err)
	// when
	_, response := test.AuditTokenOK(s.T(), goajwt.WithJWT(svc.Context, tk), svc, ctrl, res.ResourceID())
	// then
	tokenClaims, err := manager.ParseToken(svc.Context, *response.RptToken)
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
	loginService, accessToken, _ := newKeycloakOAuthMockService(s.T(), *user.Identity())
	svc, ctrl := s.SecuredControllerWithIdentity(*user.Identity(), loginService)
	manager, err := token.NewManager(s.Configuration)
	require.Nil(s.T(), err)
	tk, err := manager.Parse(s.Ctx, accessToken)
	require.NoError(s.T(), err)
	// when
	_, response := test.AuditTokenOK(s.T(), goajwt.WithJWT(svc.Context, tk), svc, ctrl, res.ResourceID())
	// then
	tokenClaims, err := manager.ParseToken(svc.Context, *response.RptToken)
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
	rptToken, err := manager.Parse(s.Ctx, *response.RptToken)
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
	loginService, accessToken, _ := newKeycloakOAuthMockService(s.T(), *user.Identity())
	svc, ctrl := s.SecuredControllerWithIdentity(*user.Identity(), loginService)
	manager, err := token.NewManager(s.Configuration)
	require.Nil(s.T(), err)
	tk, err := manager.Parse(s.Ctx, accessToken)
	require.NoError(s.T(), err)
	// when
	_, response := test.AuditTokenOK(s.T(), goajwt.WithJWT(svc.Context, tk), svc, ctrl, res.ResourceID())
	// then
	tokenClaims, err := manager.ParseToken(svc.Context, *response.RptToken)
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
	rptToken, err := manager.Parse(s.Ctx, *response.RptToken)
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

func (s *TokenControllerTestSuite) checkServiceAccountCredentials(name string, id string, secret string) {
	loginService, _, _ := newKeycloakOAuthMockService(s.T(), testsupport.TestIdentity)
	svc, ctrl := s.SecuredController(loginService)

	_, saToken := test.ExchangeTokenOK(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "client_credentials", ClientSecret: &secret, ClientID: id})
	assert.NotNil(s.T(), saToken.TokenType)
	assert.Equal(s.T(), "bearer", *saToken.TokenType)
	assert.NotNil(s.T(), saToken.AccessToken)
	claims, err := testtoken.TokenManager.ParseTokenWithMapClaims(context.Background(), *saToken.AccessToken)
	require.Nil(s.T(), err)

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	ctx := goajwt.WithJWT(context.Background(), jwtToken)
	assert.True(s.T(), token.IsServiceAccount(ctx))
	assert.True(s.T(), token.IsSpecificServiceAccount(ctx, name))
}

func (s *TokenControllerTestSuite) checkAuthorizationCode(svc *goa.Service, ctrl *TokenController, name string, code string, expectedAccessToken string, expectedRefreshToken string) {
	_, token := test.ExchangeTokenOK(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "authorization_code", ClientID: s.Configuration.GetPublicOauthClientID(), Code: &code})

	require.NotNil(s.T(), token)
	require.NotNil(s.T(), token.TokenType)
	require.Equal(s.T(), "bearer", *token.TokenType)
	require.NotNil(s.T(), token.AccessToken)
	assert.NoError(s.T(), testtoken.EqualAccessTokens(context.Background(), expectedAccessToken, *token.AccessToken))
	require.NotNil(s.T(), token.RefreshToken)
	assert.NoError(s.T(), testtoken.EqualRefreshTokens(context.Background(), expectedRefreshToken, *token.RefreshToken))
	expiresIn, err := strconv.Atoi(*token.ExpiresIn)
	require.Nil(s.T(), err)
	require.True(s.T(), expiresIn > 60*59*24*30 && expiresIn < 60*61*24*30) // The expires_in should be withing a minute range of 30 days.
}

func (s *TokenControllerTestSuite) checkExchangeWithRefreshToken(svc *goa.Service, ctrl *TokenController, name string, refreshToken string, expectedAccessToken, expectedRefreshToken string) {
	_, token := test.ExchangeTokenOK(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "refresh_token", ClientID: s.Configuration.GetPublicOauthClientID(), RefreshToken: &refreshToken})

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
	tokenManager, err := token.NewManager(s.Configuration)
	require.Nil(s.T(), err)
	oauthService := &NotApprovedOAuthService{}
	ctrl := NewTokenController(svc, s.Application, oauthService, &DummyLinkService{}, nil, tokenManager, s.Configuration)

	code := "XYZ"
	_, errResp := test.ExchangeTokenForbidden(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "authorization_code", ClientID: s.Configuration.GetPublicOauthClientID(), Code: &code})
	require.Equal(s.T(), "user is not authorized to access OpenShift", errResp.Errors[0].Detail)

	oauthService = &NotApprovedOAuthService{}
	oauthService.Scenario = "approved"
	ctrl = NewTokenController(svc, s.Application, oauthService, &DummyLinkService{}, nil, tokenManager, s.Configuration)

	code = "XYZ"
	_, returnedToken := test.ExchangeTokenOK(s.T(), svc.Context, svc, ctrl, &app.TokenExchange{GrantType: "authorization_code", ClientID: s.Configuration.GetPublicOauthClientID(), Code: &code})
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

func newKeycloakOAuthMockService(t *testing.T, identity account.Identity) (login.KeycloakOAuthService, string, string) {
	loginService := testlogin.NewKeycloakOAuthServiceMock(t)
	tokenSet, err := testtoken.GenerateUserTokenForIdentity(context.Background(), identity, false)
	require.Nil(t, err)
	loginService.ExchangeFunc = func(ctx context.Context, code string, config oauth.OauthConfig) (*oauth2.Token, error) {
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
	loginService.ExchangeRefreshTokenFunc = func(ctx context.Context, accessToken, refreshToken string, serviceConfig login.Configuration) (*token.TokenSet, error) {
		var thirtyDays int64
		thirtyDays = 60 * 60 * 24 * 30
		bearer := "Bearer"
		token := &token.TokenSet{
			TokenType:    &bearer,
			AccessToken:  &tokenSet.AccessToken,
			RefreshToken: &tokenSet.RefreshToken,
			ExpiresIn:    &thirtyDays,
		}
		return token, nil
	}
	loginService.CreateOrUpdateIdentityAndUserFunc = func(ctx context.Context, referrerURL *url.URL, keycloakToken *oauth2.Token, request *goa.RequestData, config oauth.IdentityProvider, serviceConfig login.Configuration) (*string, *oauth2.Token, error) {
		var thirtyDays, nbf int64
		thirtyDays = 60 * 60 * 24 * 30
		token := &oauth2.Token{
			TokenType:    "bearer",
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
	return loginService, tokenSet.AccessToken, tokenSet.RefreshToken
}

type NotApprovedOAuthService struct {
	login.KeycloakOAuthProvider
	Scenario string
}

func (s *NotApprovedOAuthService) Exchange(ctx context.Context, code string, config oauth.OauthConfig) (*oauth2.Token, error) {
	bearer := "Bearer"
	token := &oauth2.Token{
		TokenType:    bearer,
		AccessToken:  "sometoken",
		RefreshToken: "sometoken",
	}
	return token, nil
}

func (s *NotApprovedOAuthService) CreateOrUpdateIdentityInDB(ctx context.Context, accessToken string, config oauth.IdentityProvider, configuration login.Configuration) (*account.Identity, bool, error) {
	return nil, false, errors.NewUnauthorizedError("user is absent")
}
func (s *NotApprovedOAuthService) CreateOrUpdateIdentityAndUser(ctx context.Context, referrerURL *url.URL, keycloakToken *oauth2.Token, request *goa.RequestData, config oauth.IdentityProvider, serviceConfig login.Configuration) (*string, *oauth2.Token, error) {

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
