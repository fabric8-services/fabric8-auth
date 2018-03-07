package controller_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/login"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/fabric8-services/fabric8-auth/token/oauth"
	"github.com/fabric8-services/fabric8-auth/wit"

	"github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"golang.org/x/oauth2"
)

type TestTokenREST struct {
	gormtestsupport.DBTestSuite
	sampleAccessToken  string
	sampleRefreshToken string
	exchangeStrategy   string
}

func TestRunTokenREST(t *testing.T) {
	suite.Run(
		t,
		&TestTokenREST{
			DBTestSuite: gormtestsupport.NewDBTestSuite(),
		})
}

func (rest *TestTokenREST) SetupSuite() {
	rest.DBTestSuite.SetupSuite()

	claims := make(map[string]interface{})
	act, err := testtoken.GenerateTokenWithClaims(claims)
	require.Nil(rest.T(), err)
	rest.sampleAccessToken = act
	rest.sampleRefreshToken = uuid.NewV4().String()
}

func (rest *TestTokenREST) SetupTest() {
	rest.DBTestSuite.SetupTest()
	rest.exchangeStrategy = ""
}

func (rest *TestTokenREST) SecuredControllerWithNonExistentIdentity() (*goa.Service, *TokenController) {
	return rest.SecuredControllerWithIdentity(testsupport.TestIdentity)
}

func (rest *TestTokenREST) SecuredController() (*goa.Service, *TokenController) {
	identity, err := testsupport.CreateTestIdentity(rest.DB, uuid.NewV4().String(), "KC")
	require.Nil(rest.T(), err)
	return rest.SecuredControllerWithIdentity(identity)
}

func (rest *TestTokenREST) SecuredControllerWithIdentity(identity account.Identity) (*goa.Service, *TokenController) {
	newTestKeycloakOAuthProvider(rest.Application)
	loginService := &DummyKeycloakOAuthService{}
	profileService := login.NewKeycloakUserProfileClient()
	loginService.KeycloakOAuthProvider = *login.NewKeycloakOAuthProvider(rest.Application.Identities(), rest.Application.Users(), testtoken.TokenManager, rest.Application, profileService, nil)
	loginService.Identities = rest.Application.Identities()
	loginService.Users = rest.Application.Users()
	loginService.TokenManager = testtoken.TokenManager
	loginService.DB = rest.Application
	loginService.RemoteWITService = &wit.RemoteWITServiceCaller{}
	loginService.exchangeStrategy = rest.exchangeStrategy
	loginService.accessToken = rest.sampleAccessToken
	loginService.refreshToken = rest.sampleRefreshToken

	svc := testsupport.ServiceAsUser("Token-Service", identity)

	linkService := &DummyLinkService{}
	return svc, NewTokenController(svc, rest.Application, loginService, linkService, nil, loginService.TokenManager, newMockKeycloakExternalTokenServiceClient(), rest.Configuration)
}

func (rest *TestTokenREST) TestRefreshTokenUsingNilTokenFails() {
	t := rest.T()
	service, controller := rest.SecuredController()

	payload := &app.RefreshToken{}
	_, err := test.RefreshTokenBadRequest(t, service.Context, service, controller, payload)
	assert.NotNil(t, err)
}

func (rest *TestTokenREST) TestRefreshTokenUsingWrongRefreshTokenFails() {
	t := rest.T()
	rest.exchangeStrategy = "401"
	service, controller := rest.SecuredController()

	refreshToken := "WRONG_REFRESH_TOKEN"
	payload := &app.RefreshToken{
		RefreshToken: &refreshToken,
	}
	test.RefreshTokenUnauthorized(t, service.Context, service, controller, payload)
}

func (rest *TestTokenREST) TestRefreshTokenUsingCorrectRefreshTokenOK() {
	t := rest.T()
	service, controller := rest.SecuredController()

	refreshToken := "SOME_REFRESH_TOKEN"
	payload := &app.RefreshToken{
		RefreshToken: &refreshToken,
	}
	_, authToken := test.RefreshTokenOK(t, service.Context, service, controller, payload)
	token := authToken.Token
	require.NotNil(rest.T(), token.TokenType)
	require.Equal(rest.T(), "bearer", *token.TokenType)
	require.NotNil(rest.T(), token.AccessToken)
	require.Equal(rest.T(), rest.sampleAccessToken, *token.AccessToken)
	require.NotNil(rest.T(), token.RefreshToken)
	require.Equal(rest.T(), rest.sampleRefreshToken, *token.RefreshToken)
	expiresIn, ok := token.ExpiresIn.(*int64)
	require.True(rest.T(), ok)
	require.True(rest.T(), *expiresIn > 60*59*24*30 && *expiresIn < 60*61*24*30) // The expires_in should be withing a minute range of 30 days.
}
func (rest *TestTokenREST) TestLinkForNonExistentUserFails() {
	service, controller := rest.SecuredControllerWithNonExistentIdentity()

	redirect := "https://openshift.io"
	test.LinkTokenUnauthorized(rest.T(), service.Context, service, controller, "https://github.com/org/repo", &redirect)
}

func (rest *TestTokenREST) TestLinkNoRedirectNoReferrerFails() {
	service, controller := rest.SecuredController()

	test.LinkTokenBadRequest(rest.T(), service.Context, service, controller, "https://github.com/org/repo", nil)
}

func (rest *TestTokenREST) TestLinkOK() {
	service, controller := rest.SecuredController()

	redirect := "https://openshift.io"
	_, redirectLocation := test.LinkTokenOK(rest.T(), service.Context, service, controller, "https://github.com/org/repo", &redirect)
	require.NotNil(rest.T(), redirectLocation)
	require.Equal(rest.T(), "providerLocation", redirectLocation.RedirectLocation)

	// Multiple "for" resources
	_, redirectLocation = test.LinkTokenOK(rest.T(), service.Context, service, controller, "https://github.com/org/repo,"+rest.Configuration.GetOpenShiftClientApiUrl(), &redirect)
	require.NotNil(rest.T(), redirectLocation)
	require.Equal(rest.T(), "providerLocation", redirectLocation.RedirectLocation)
}

func (rest *TestTokenREST) TestLinkCallbackRedirects() {
	service, controller := rest.SecuredController()

	response := test.CallbackTokenTemporaryRedirect(rest.T(), service.Context, service, controller, "", "")
	require.NotNil(rest.T(), response)
	location := response.Header()["Location"]
	require.Equal(rest.T(), 1, len(location))
	require.Equal(rest.T(), "originalLocation", location[0])
}

func (rest *TestTokenREST) TestExchangeFailsWithIncompletePayload() {
	service, controller := rest.SecuredController()

	someRandomString := "someString"
	test.ExchangeTokenBadRequest(rest.T(), service.Context, service, controller, &app.TokenExchange{GrantType: "client_credentials", ClientID: someRandomString})
	test.ExchangeTokenBadRequest(rest.T(), service.Context, service, controller, &app.TokenExchange{GrantType: "authorization_code", ClientID: someRandomString})
	test.ExchangeTokenBadRequest(rest.T(), service.Context, service, controller, &app.TokenExchange{GrantType: "authorization_code", ClientID: someRandomString, RedirectURI: &someRandomString})
	test.ExchangeTokenBadRequest(rest.T(), service.Context, service, controller, &app.TokenExchange{GrantType: "refresh_token", ClientID: someRandomString})
}

func (rest *TestTokenREST) TestExchangeWithWrongCredentialsFails() {
	service, controller := rest.SecuredController()

	someRandomString := "someString"
	witID := "fabric8-wit"
	test.ExchangeTokenUnauthorized(rest.T(), service.Context, service, controller, &app.TokenExchange{GrantType: "client_credentials", ClientSecret: &someRandomString, ClientID: someRandomString})
	test.ExchangeTokenUnauthorized(rest.T(), service.Context, service, controller, &app.TokenExchange{GrantType: "client_credentials", ClientSecret: &someRandomString, ClientID: witID})
}

func (rest *TestTokenREST) TestExchangeWithCorrectCredentialsOK() {
	rest.checkServiceAccountCredentials("fabric8-wit", "5dec5fdb-09e3-4453-b73f-5c828832b28e", "witsecret")
	rest.checkServiceAccountCredentials("fabric8-tenant", "c211f1bd-17a7-4f8c-9f80-0917d167889d", "tenantsecretOld")
	rest.checkServiceAccountCredentials("fabric8-tenant", "c211f1bd-17a7-4f8c-9f80-0917d167889d", "tenantsecretNew")
}

func (rest *TestTokenREST) TestExchangeWithWrongCodeFails() {
	rest.exchangeStrategy = "401"
	service, controller := rest.SecuredController()

	someRandomString := "someString"
	clientID := controller.Configuration.GetPublicOauthClientID()
	code := "INVALID_OAUTH2.0_CODE"
	test.ExchangeTokenUnauthorized(rest.T(), service.Context, service, controller, &app.TokenExchange{GrantType: "authorization_code", RedirectURI: &someRandomString, ClientID: clientID, Code: &code})

	test.ExchangeTokenBadRequest(rest.T(), service.Context, service, controller, &app.TokenExchange{GrantType: "authorization_code", RedirectURI: &someRandomString, ClientID: clientID})
}

func (rest *TestTokenREST) TestExchangeWithWrongClientIDFails() {
	service, controller := rest.SecuredController()

	someRandomString := "someString"
	clientID := "someString"
	code := "doesnt_matter"
	refreshToken := "doesnt_matter "
	test.ExchangeTokenUnauthorized(rest.T(), service.Context, service, controller, &app.TokenExchange{GrantType: "authorization_code", RedirectURI: &someRandomString, ClientID: clientID, Code: &code})
	test.ExchangeTokenUnauthorized(rest.T(), service.Context, service, controller, &app.TokenExchange{GrantType: "refresh_token", ClientID: clientID, RefreshToken: &refreshToken})
}

func (rest *TestTokenREST) TestExchangeFailsWithWrongRefreshToken() {
	rest.exchangeStrategy = "401"
	service, controller := rest.SecuredController()
	clientID := controller.Configuration.GetPublicOauthClientID()
	refreshToken := "INVALID_REFRESH_TOKEN"

	test.ExchangeTokenUnauthorized(rest.T(), service.Context, service, controller, &app.TokenExchange{GrantType: "refresh_token", ClientID: clientID, RefreshToken: &refreshToken})
}

func (rest *TestTokenREST) TestExchangeWithCorrectCodeOK() {
	service, controller := rest.SecuredController()
	rest.checkAuthorizationCode(service, controller, controller.Configuration.GetPublicOauthClientID(), "SOME_OAUTH2.0_CODE")
}

func (rest *TestTokenREST) TestExchangeWithCorrectRefreshTokenOK() {
	service, controller := rest.SecuredController()
	rest.checkExchangeWithRefreshToken(service, controller, controller.Configuration.GetPublicOauthClientID(), "SOME_REFRESH_TOKEN")
}

func (rest *TestTokenREST) checkServiceAccountCredentials(name string, id string, secret string) {
	service, controller := rest.SecuredController()

	_, saToken := test.ExchangeTokenOK(rest.T(), service.Context, service, controller, &app.TokenExchange{GrantType: "client_credentials", ClientSecret: &secret, ClientID: id})
	assert.NotNil(rest.T(), saToken.TokenType)
	assert.Equal(rest.T(), "bearer", *saToken.TokenType)
	assert.NotNil(rest.T(), saToken.AccessToken)
	claims, err := testtoken.TokenManager.ParseTokenWithMapClaims(context.Background(), *saToken.AccessToken)
	require.Nil(rest.T(), err)

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	ctx := goajwt.WithJWT(context.Background(), jwtToken)
	assert.True(rest.T(), token.IsServiceAccount(ctx))
	assert.True(rest.T(), token.IsSpecificServiceAccount(ctx, name))
}

func (rest *TestTokenREST) checkAuthorizationCode(service *goa.Service, controller *TokenController, name string, code string) {
	_, token := test.ExchangeTokenOK(rest.T(), service.Context, service, controller, &app.TokenExchange{GrantType: "authorization_code", ClientID: rest.Configuration.GetPublicOauthClientID(), Code: &code})

	require.NotNil(rest.T(), token.TokenType)
	require.Equal(rest.T(), "bearer", *token.TokenType)
	require.NotNil(rest.T(), token.AccessToken)
	require.Equal(rest.T(), rest.sampleAccessToken, *token.AccessToken)
	require.NotNil(rest.T(), token.RefreshToken)
	require.Equal(rest.T(), rest.sampleRefreshToken, *token.RefreshToken)
	expiresIn, err := strconv.Atoi(*token.ExpiresIn)
	require.Nil(rest.T(), err)
	require.True(rest.T(), expiresIn > 60*59*24*30 && expiresIn < 60*61*24*30) // The expires_in should be withing a minute range of 30 days.
}

func (rest *TestTokenREST) checkExchangeWithRefreshToken(service *goa.Service, controller *TokenController, name string, refreshToken string) {
	_, token := test.ExchangeTokenOK(rest.T(), service.Context, service, controller, &app.TokenExchange{GrantType: "refresh_token", ClientID: rest.Configuration.GetPublicOauthClientID(), RefreshToken: &refreshToken})

	require.NotNil(rest.T(), token.TokenType)
	require.Equal(rest.T(), "bearer", *token.TokenType)
	require.NotNil(rest.T(), token.AccessToken)
	require.Equal(rest.T(), rest.sampleAccessToken, *token.AccessToken)
	require.NotNil(rest.T(), token.RefreshToken)
	require.Equal(rest.T(), rest.sampleRefreshToken, *token.RefreshToken)
	expiresIn, err := strconv.Atoi(*token.ExpiresIn)
	require.Nil(rest.T(), err)
	require.True(rest.T(), expiresIn > 60*59*24*30 && expiresIn < 60*61*24*30) // The expires_in should be withing a minute range of 30 days.
}

type DummyLinkService struct {
}

func (s *DummyLinkService) ProviderLocation(ctx context.Context, req *goa.RequestData, identityID string, forResource string, redirectURL string) (string, error) {
	return "providerLocation", nil
}

func (s *DummyLinkService) Callback(ctx context.Context, req *goa.RequestData, state string, code string) (string, error) {
	return "originalLocation", nil
}

type DummyKeycloakOAuthService struct {
	login.KeycloakOAuthProvider
	accessToken      string
	refreshToken     string
	exchangeStrategy string
}

func (s *DummyKeycloakOAuthService) Exchange(ctx context.Context, code string, config oauth.OauthConfig) (*oauth2.Token, error) {
	if s.exchangeStrategy == "401" {
		return nil, errors.NewUnauthorizedError("failed")
	}
	var thirtyDays int64
	thirtyDays = 60 * 60 * 24 * 30
	token := &oauth2.Token{
		TokenType:    "bearer",
		AccessToken:  s.accessToken,
		RefreshToken: s.refreshToken,
		Expiry:       time.Unix(time.Now().Unix()+thirtyDays, 0),
	}
	extra := make(map[string]interface{})
	extra["expires_in"] = thirtyDays
	extra["refresh_expires_in"] = thirtyDays
	token = token.WithExtra(extra)
	return token, nil
}

func (s *DummyKeycloakOAuthService) ExchangeRefreshToken(ctx context.Context, refreshToken string, endpoint string, serviceConfig login.LoginServiceConfiguration) (*token.TokenSet, error) {
	if s.exchangeStrategy == "401" {
		return nil, errors.NewUnauthorizedError("failed")
	}

	var thirtyDays int64
	thirtyDays = 60 * 60 * 24 * 30
	bearer := "bearer"
	token := &token.TokenSet{
		TokenType:    &bearer,
		AccessToken:  &s.accessToken,
		RefreshToken: &s.refreshToken,
		ExpiresIn:    &thirtyDays,
	}
	return token, nil
}
