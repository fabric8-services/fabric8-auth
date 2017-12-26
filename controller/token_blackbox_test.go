package controller_test

import (
	"context"
	rand "math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/fabric8-services/fabric8-auth/token"
	netcontext "golang.org/x/net/context"
	"golang.org/x/oauth2"

	"github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestTokenREST struct {
	gormtestsupport.DBTestSuite
	dummyOauth         dummyOauth2Config
	sampleAccessToken  string
	sampleRefreshToken string
}

type dummyOauth2Config struct {
	oauth2.Config
	accessToken string
}

func TestRunTokenREST(t *testing.T) {
	suite.Run(
		t,
		&TestTokenREST{
			DBTestSuite:        gormtestsupport.NewDBTestSuite(),
			sampleAccessToken:  strconv.Itoa(rand.Int()),
			sampleRefreshToken: strconv.Itoa(rand.Int()),
		})
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
	loginService := newTestKeycloakOAuthProvider(rest.Application)

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

}

func (rest *TestTokenREST) TestExchangeWithWrongCredentialsFails() {
	service, controller := rest.SecuredController()

	someRandomString := "someString"
	witID := "fabric8-wit"
	test.ExchangeTokenUnauthorized(rest.T(), service.Context, service, controller, &app.TokenExchange{GrantType: "client_credentials", ClientSecret: &someRandomString, ClientID: someRandomString})
	test.ExchangeTokenUnauthorized(rest.T(), service.Context, service, controller, &app.TokenExchange{GrantType: "client_credentials", ClientSecret: &someRandomString, ClientID: witID})
}

func (rest *TestTokenREST) TestExchangeWithWrongCodeFails() {
	service, controller := rest.SecuredController()

	someRandomString := "someString"
	clientID := controller.Configuration.GetPublicOauthClientID()
	code := "INVALID_OAUTH2.0_CODE"
	test.ExchangeTokenUnauthorized(rest.T(), service.Context, service, controller, &app.TokenExchange{GrantType: "authorization_code", RedirectURI: &someRandomString, ClientID: clientID, Code: &code})

}

func (rest *TestTokenREST) TestExchangeWithWrongClientIDFailsWithGrantTypeAuthorizationCode() {
	service, controller := rest.SecuredController()

	someRandomString := "someString"
	clientID := "someString"
	code := "doesnt_matter"
	test.ExchangeTokenUnauthorized(rest.T(), service.Context, service, controller, &app.TokenExchange{GrantType: "authorization_code", RedirectURI: &someRandomString, ClientID: clientID, Code: &code})
}

func (rest *TestTokenREST) TestExchangeWithCorrectCredentialsOK() {
	rest.checkServiceAccountCredentials("fabric8-wit", "5dec5fdb-09e3-4453-b73f-5c828832b28e", "witsecret")
	rest.checkServiceAccountCredentials("fabric8-tenant", "c211f1bd-17a7-4f8c-9f80-0917d167889d", "tenantsecretOld")
	rest.checkServiceAccountCredentials("fabric8-tenant", "c211f1bd-17a7-4f8c-9f80-0917d167889d", "tenantsecretNew")
}

func (rest *TestTokenREST) TestExchangeWithCorrectCodeOK() {
	_, controller := rest.SecuredController()
	rest.checkAuthorizationCode(controller.Configuration.GetPublicOauthClientID(), "SOME_OAUTH2.0_CODE")
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

func (rest *TestTokenREST) checkAuthorizationCode(name string, code string) {
	service, _ := rest.SecuredController()
	saToken, err := rest.Exchange(service.Context, code)
	assert.Nil(rest.T(), err)
	assert.NotNil(rest.T(), saToken.TokenType)
	assert.Equal(rest.T(), "bearer", saToken.TokenType)
	assert.NotNil(rest.T(), saToken.AccessToken)
	assert.Equal(rest.T(), saToken.AccessToken, rest.sampleAccessToken)
	assert.NotNil(rest.T(), saToken.RefreshToken)
	assert.Equal(rest.T(), saToken.RefreshToken, rest.sampleRefreshToken)
}

func (rest *TestTokenREST) Exchange(ctx netcontext.Context, code string) (*oauth2.Token, error) {
	var thirtyDays int64
	thirtyDays = 60 * 60 * 24 * 30
	token := &oauth2.Token{
		TokenType:    "bearer",
		AccessToken:  rest.sampleAccessToken,
		RefreshToken: rest.sampleRefreshToken,
		Expiry:       time.Unix(time.Now().Unix()+thirtyDays, 0),
	}
	extra := make(map[string]interface{})
	extra["expires_in"] = time.Now().Unix() + thirtyDays
	extra["refresh_expires_in"] = time.Now().Unix() + thirtyDays
	token = token.WithExtra(extra)
	return token, nil
}

func validateToken(t *testing.T, token *app.AuthToken, controler *TokenController) {
	assert.NotNil(t, token, "Token data is nil")
	assert.NotEmpty(t, token.Token.AccessToken, "Access token is empty")
	assert.NotEmpty(t, token.Token.RefreshToken, "Refresh token is empty")
	assert.NotEmpty(t, token.Token.TokenType, "Token type is empty")
	assert.NotNil(t, token.Token.ExpiresIn, "Expires-in is nil")
	assert.NotNil(t, token.Token.RefreshExpiresIn, "Refresh-expires-in is nil")
	assert.NotNil(t, token.Token.NotBeforePolicy, "Not-before-policy is nil")
}

type DummyLinkService struct {
}

func (s *DummyLinkService) ProviderLocation(ctx context.Context, req *goa.RequestData, identityID string, forResource string, redirectURL string) (string, error) {
	return "providerLocation", nil
}

func (s *DummyLinkService) Callback(ctx context.Context, req *goa.RequestData, state string, code string) (string, error) {
	return "originalLocation", nil
}
