package login_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/client"
	"github.com/fabric8-services/fabric8-auth/configuration"
	config "github.com/fabric8-services/fabric8-auth/configuration"
	autherrors "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	. "github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/resource"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/fabric8-services/fabric8-auth/token"

	"github.com/goadesign/goa"
	"github.com/goadesign/goa/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	netcontext "golang.org/x/net/context"
	"golang.org/x/oauth2"
)

type serviceBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	loginService           *KeycloakOAuthProvider
	oauth                  *oauth2.Config
	dummyOauth             *dummyOauth2Config
	keycloakTokenService   *DummyTokenService
	osoSubscriptionManager *testsupport.DummyOSORegistrationApp
}

func TestRunServiceBlackBoxTest(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &serviceBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

// SetupSuite overrides the DBTestSuite's function but calls it before doing anything else
// The SetupSuite method will run before the tests in the suite are run.
// It sets up a database connection for all the tests in this suite without polluting global space.
func (s *serviceBlackBoxTest) SetupSuite() {
	s.DBTestSuite.SetupSuite()

	var err error
	req := &goa.RequestData{
		Request: &http.Request{Host: "api.service.domain.org"},
	}
	authEndpoint, err := s.Configuration.GetKeycloakEndpointAuth(req)
	if err != nil {
		panic(err)
	}
	tokenEndpoint, err := s.Configuration.GetKeycloakEndpointToken(req)
	if err != nil {
		panic(err)
	}
	s.oauth = &oauth2.Config{
		ClientID:     s.Configuration.GetKeycloakClientID(),
		ClientSecret: s.Configuration.GetKeycloakSecret(),
		Scopes:       []string{"user:email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  authEndpoint,
			TokenURL: tokenEndpoint,
		},
	}
	claims := make(map[string]interface{})
	claims["sub"] = uuid.NewV4().String()
	accessToken, err := testtoken.GenerateAccessTokenWithClaims(claims)
	if err != nil {
		panic(err)
	}
	refreshToken, err := testtoken.GenerateRefreshTokenWithClaims(claims)
	if err != nil {
		panic(err)
	}
	s.dummyOauth = &dummyOauth2Config{
		Config: oauth2.Config{
			ClientID:     s.Configuration.GetKeycloakClientID(),
			ClientSecret: s.Configuration.GetKeycloakSecret(),
			Scopes:       []string{"user:email"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  authEndpoint,
				TokenURL: tokenEndpoint,
			},
		},
		accessToken:  accessToken,
		refreshToken: refreshToken,
	}

	userRepository := account.NewUserRepository(s.DB)
	identityRepository := account.NewIdentityRepository(s.DB)
	userProfileClient := NewKeycloakUserProfileClient()

	refreshTokenSet := token.TokenSet{AccessToken: &accessToken, RefreshToken: &refreshToken}
	s.keycloakTokenService = &DummyTokenService{tokenSet: refreshTokenSet}
	s.osoSubscriptionManager = &testsupport.DummyOSORegistrationApp{}

	s.loginService = NewKeycloakOAuthProvider(identityRepository, userRepository, testtoken.TokenManager, s.Application, userProfileClient, s.keycloakTokenService, s.osoSubscriptionManager)
}

func (s *serviceBlackBoxTest) TestKeycloakAuthorizationRedirect() {
	rw := httptest.NewRecorder()
	u := &url.URL{
		Path: fmt.Sprintf("/api/login"),
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		panic("invalid test " + err.Error()) // bug
	}

	// The user clicks login while on ALM UI.
	// Therefore the referer would be an ALM URL.
	refererUrl := "https://alm-url.example.org/path"
	req.Header.Add("referer", refererUrl)

	prms := url.Values{}
	ctx := context.Background()
	goaCtx := goa.NewContext(goa.WithAction(ctx, "LoginTest"), rw, req, prms)
	authorizeCtx, err := app.NewLoginLoginContext(goaCtx, req, goa.New("LoginService"))
	if err != nil {
		panic("invalid test data " + err.Error()) // bug
	}
	require.Nil(s.T(), err)

	err = s.loginService.Login(authorizeCtx, s.oauth, s.Configuration)

	assert.Equal(s.T(), 307, rw.Code)
	assert.Contains(s.T(), rw.Header().Get("Location"), s.oauth.Endpoint.AuthURL)
	assert.NotEqual(s.T(), rw.Header().Get("Location"), "")
}

func (s *serviceBlackBoxTest) TestApprovedUserCreatedAndUpdated() {
	claims := make(map[string]interface{})
	token, err := testtoken.GenerateTokenWithClaims(claims)
	require.Nil(s.T(), err)

	identity, ok, err := s.loginService.CreateOrUpdateIdentityInDB(context.Background(), token, s.Configuration)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), identity)
	assert.True(s.T(), ok)
	s.checkIfTokenMatchesIdentity(token, *identity)
	assert.Equal(s.T(), s.Configuration.GetOpenShiftClientApiUrl(), identity.User.Cluster)
}

func (s *serviceBlackBoxTest) TestFeatureLevelOfUserCreatedAndUpdated() {
	claims := make(map[string]interface{})
	token, err := testtoken.GenerateTokenWithClaims(claims)
	require.Nil(s.T(), err)

	identity, ok, err := s.loginService.CreateOrUpdateIdentityInDB(context.Background(), token, s.Configuration)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), identity)
	assert.True(s.T(), ok)
	s.checkIfTokenMatchesIdentity(token, *identity)
	assert.Equal(s.T(), account.DefaultFeatureLevel, identity.User.FeatureLevel)
}

func (s *serviceBlackBoxTest) TestUnapprovedUserUnauthorized() {
	claims := make(map[string]interface{})
	claims["approved"] = false
	token, err := testtoken.GenerateTokenWithClaims(claims)
	require.Nil(s.T(), err)

	_, _, err = s.loginService.CreateOrUpdateIdentityInDB(context.Background(), token, s.Configuration)
	require.NotNil(s.T(), err)
	require.IsType(s.T(), autherrors.NewUnauthorizedError(""), err)

	_, err = s.unapprovedUserRedirected()
	require.NotNil(s.T(), err)
	require.IsType(s.T(), autherrors.NewUnauthorizedError(""), err)
}

func (s *serviceBlackBoxTest) TestUnapprovedUserRedirected() {
	env := os.Getenv("AUTH_NOTAPPROVED_REDIRECT")
	defer func() {
		os.Setenv("AUTH_NOTAPPROVED_REDIRECT", env)
		s.resetConfiguration()
	}()

	os.Setenv("AUTH_NOTAPPROVED_REDIRECT", "https://xyz.io")
	s.resetConfiguration()

	s.osoSubscriptionManager.Status = uuid.NewV4().String()
	redirect, err := s.unapprovedUserRedirected()
	require.NoError(s.T(), err)
	require.Equal(s.T(), "https://xyz.io?status="+s.osoSubscriptionManager.Status, *redirect)

	// If OSO subscription status loading failed we still should redirect
	s.osoSubscriptionManager.Status = ""
	s.osoSubscriptionManager.Err = autherrors.NewInternalError(context.Background(), errors.New(""))
	redirect, err = s.unapprovedUserRedirected()
	require.NoError(s.T(), err)
	require.Equal(s.T(), "https://xyz.io?status=", *redirect)
}

func (s *serviceBlackBoxTest) unapprovedUserRedirected() (*string, error) {
	redirect, err := url.Parse("https://openshift.io/_home")
	require.Nil(s.T(), err)

	req := &goa.RequestData{
		Request: &http.Request{Host: "auth.openshift.io"},
	}

	claims := make(map[string]interface{})
	claims["approved"] = false
	accessTokenStr, err := testtoken.GenerateAccessTokenWithClaims(claims)
	require.Nil(s.T(), err)

	refreshTokenStr, err := testtoken.GenerateRefreshTokenWithClaims(claims)
	require.Nil(s.T(), err)

	token := &oauth2.Token{AccessToken: accessTokenStr, RefreshToken: refreshTokenStr}
	redirectURL, _, err := s.loginService.CreateOrUpdateIdentityAndUser(context.Background(), redirect, token, req, s.Configuration)
	return redirectURL, err
}

func (s *serviceBlackBoxTest) resetConfiguration() {
	var err error
	s.Configuration, err = configuration.GetConfigurationData()
	require.Nil(s.T(), err)
}

func (s *serviceBlackBoxTest) checkIfTokenMatchesIdentity(tokenString string, identity account.Identity) {
	claims, err := testtoken.TokenManager.ParseToken(context.Background(), tokenString)
	require.Nil(s.T(), err)
	assert.Equal(s.T(), claims.Company, identity.User.Company)
	assert.Equal(s.T(), claims.Username, identity.Username)
	assert.Equal(s.T(), claims.Email, identity.User.Email)
	assert.Equal(s.T(), claims.Subject, identity.ID.String())
	assert.Equal(s.T(), claims.Name, identity.User.FullName)
}

func (s *serviceBlackBoxTest) TestKeycloakAuthorizationRedirectsToRedirectParam() {
	rw := httptest.NewRecorder()
	redirect := "https://url.example.org/pathredirect"
	u := &url.URL{
		Path: fmt.Sprintf("/api/login?redirect="),
	}
	parameters := url.Values{}
	if redirect != "" {
		parameters.Add("redirect", redirect)
	}

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		panic("invalid test " + err.Error()) // bug
	}

	ctx := context.Background()
	goaCtx := goa.NewContext(goa.WithAction(ctx, "LoginTest"), rw, req, parameters)
	authorizeCtx, err := app.NewLoginLoginContext(goaCtx, req, goa.New("LoginService"))
	if err != nil {
		panic("invalid test data " + err.Error()) // bug
	}

	require.Nil(s.T(), err)

	err = s.loginService.Login(authorizeCtx, s.oauth, s.Configuration)

	assert.Equal(s.T(), 307, rw.Code)
	assert.Contains(s.T(), rw.Header().Get("Location"), s.oauth.Endpoint.AuthURL)
	assert.NotEqual(s.T(), rw.Header().Get("Location"), "")
}

func (s *serviceBlackBoxTest) TestKeycloakAuthorizationWithNoRefererAndRedirectParamFails() {
	rw := httptest.NewRecorder()
	u := &url.URL{
		Path: fmt.Sprintf("/api/login"),
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		panic("invalid test " + err.Error()) // bug
	}

	prms := url.Values{}
	ctx := context.Background()
	goaCtx := goa.NewContext(goa.WithAction(ctx, "LoginTest"), rw, req, prms)
	authorizeCtx, err := app.NewLoginLoginContext(goaCtx, req, goa.New("LoginService"))
	if err != nil {
		panic("invalid test data " + err.Error()) // bug
	}
	require.Nil(s.T(), err)

	err = s.loginService.Login(authorizeCtx, s.oauth, s.Configuration)
	assert.Equal(s.T(), 400, rw.Code)
}

func (s *serviceBlackBoxTest) TestKeycloakAuthorizationWithNoValidRefererFails() {

	// since we no longer pass the valid redirect urls as a parameter,
	existingValidRedirects := os.Getenv("AUTH_REDIRECT_VALID")
	defer func() {
		os.Setenv("AUTH_REDIRECT_VALID", existingValidRedirects)
		config, err := config.GetConfigurationData()
		assert.Nil(s.T(), err)
		s.Configuration = config
	}()
	os.Setenv("AUTH_REDIRECT_VALID", config.DefaultValidRedirectURLs)

	// Start running the actual test in Non-dev mode.

	rw := httptest.NewRecorder()
	u := &url.URL{
		Path: fmt.Sprintf("/api/login"),
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		panic("invalid test " + err.Error()) // bug
	}

	// Not whitelisted redirect fails
	prms := url.Values{}
	prms.Add("redirect", "http://notauthorized.domain.com")

	ctx := context.Background()
	goaCtx := goa.NewContext(goa.WithAction(ctx, "LoginTest"), rw, req, prms)
	authorizeCtx, err := app.NewLoginLoginContext(goaCtx, req, goa.New("LoginService"))
	if err != nil {
		panic("invalid test data " + err.Error()) // bug
	}
	require.Nil(s.T(), err)

	err = s.loginService.Login(authorizeCtx, s.oauth, s.Configuration)
	assert.Equal(s.T(), 400, rw.Code)

	// openshift.io redirects pass
	rw = httptest.NewRecorder()
	prms = url.Values{}
	prms.Add("redirect", "https://openshift.io/somepath")

	goaCtx = goa.NewContext(goa.WithAction(ctx, "LoginTest"), rw, req, prms)
	authorizeCtx, err = app.NewLoginLoginContext(goaCtx, req, goa.New("LoginService"))
	if err != nil {
		panic("invalid test data " + err.Error()) // bug
	}

	err = s.loginService.Login(authorizeCtx, s.oauth, s.Configuration)
	assert.Equal(s.T(), 307, rw.Code)
	assert.Contains(s.T(), rw.Header().Get("Location"), s.oauth.Endpoint.AuthURL)
	assert.NotEqual(s.T(), rw.Header().Get("Location"), "")

}
func (s *serviceBlackBoxTest) TestKeycloakAuthorizationDevModePasses() {
	// Any redirects pass in Dev mode.
	u := &url.URL{
		Path: fmt.Sprintf("/api/login"),
	}
	rw := httptest.NewRecorder()
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		panic("invalid test " + err.Error()) // bug
	}
	prms := url.Values{}
	prms.Add("redirect", "https://anydoamin.io/somepath")

	ctx := context.Background()
	goaCtx := goa.NewContext(goa.WithAction(ctx, "LoginTest"), rw, req, prms)
	authorizeCtx, err := app.NewLoginLoginContext(goaCtx, req, goa.New("LoginService"))
	if err != nil {
		panic("invalid test data " + err.Error()) // bug
	}

	err = s.loginService.Login(authorizeCtx, s.oauth, s.Configuration)
	assert.Equal(s.T(), 307, rw.Code)
	assert.Contains(s.T(), rw.Header().Get("Location"), s.oauth.Endpoint.AuthURL)
	assert.NotEqual(s.T(), rw.Header().Get("Location"), "")
}

func (s *serviceBlackBoxTest) TestInvalidState() {
	// Setup request context
	rw := httptest.NewRecorder()
	u := &url.URL{
		Path: fmt.Sprintf("/api/login"),
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		panic("invalid test " + err.Error()) // bug
	}

	// The OAuth 'state' is sent as a query parameter by calling /api/login/authorize?code=_SOME_CODE_&state=_SOME_STATE_
	// The request originates from Keycloak after a valid authorization by the end user.
	// This is not where the redirection should happen on failure.
	refererKeycloakUrl := "https://keycloak-url.example.org/path-of-login"
	req.Header.Add("referer", refererKeycloakUrl)

	prms := url.Values{
		"state": {},
		"code":  {"doesnt_matter_what_is_here"},
	}
	ctx := context.Background()
	goaCtx := goa.NewContext(goa.WithAction(ctx, "LoginTest"), rw, req, prms)
	authorizeCtx, err := app.NewLoginLoginContext(goaCtx, req, goa.New("LoginService"))
	require.Nil(s.T(), err)
	err = s.loginService.Login(authorizeCtx, s.oauth, s.Configuration)
	assert.Equal(s.T(), 401, rw.Code)
}

func (s *serviceBlackBoxTest) TestInvalidOAuthAuthorizationCode() {

	// When a valid referrer talks to our system and provides
	// an invalid OAuth2.0 code, the access token exchange
	// fails. In such a scenario, there is response redirection
	// to the valid referer, ie, the URL where the request originated from.
	// Currently, this should be something like https://demo.openshift.io/somepage/

	// Setup request context
	rw := httptest.NewRecorder()
	u := &url.URL{
		Path: fmt.Sprintf("/api/login"),
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		panic("invalid test " + err.Error()) // bug
	}

	// The user clicks login while on ALM UI.
	// Therefore the referer would be an ALM URL.
	refererUrl := "https://wit-url.example.org/path"
	req.Header.Add("referer", refererUrl)

	prms := url.Values{}
	ctx := context.Background()
	goaCtx := goa.NewContext(goa.WithAction(ctx, "LoginTest"), rw, req, prms)
	authorizeCtx, err := app.NewLoginLoginContext(goaCtx, req, goa.New("LoginService"))
	require.Nil(s.T(), err)

	err = s.loginService.Login(authorizeCtx, s.oauth, s.Configuration)

	assert.Equal(s.T(), 307, rw.Code) // redirect to keycloak login page.

	locationString := rw.HeaderMap["Location"][0]
	locationUrl, err := url.Parse(locationString)
	require.Nil(s.T(), err)

	allQueryParameters := locationUrl.Query()

	// Avoiding panics.
	assert.NotNil(s.T(), allQueryParameters)
	assert.NotNil(s.T(), allQueryParameters["state"][0])

	returnedState := allQueryParameters["state"][0]

	prms = url.Values{
		"state": {returnedState},
		"code":  {"INVALID_OAUTH2.0_CODE"},
	}
	ctx = context.Background()
	rw = httptest.NewRecorder()

	req, err = http.NewRequest("GET", u.String(), nil)

	// The OAuth code is sent as a query parameter by calling /api/login/authorize?code=_SOME_CODE_&state=_SOME_STATE_
	// The request originates from Keycloak after a valid authorization by the end user.
	// This is not where the redirection should happen on failure.
	refererKeycloakUrl := "https://keycloak-url.example.org/path-of-login"
	req.Header.Add("referer", refererKeycloakUrl)
	require.Nil(s.T(), err)

	goaCtx = goa.NewContext(goa.WithAction(ctx, "LoginTest"), rw, req, prms)
	authorizeCtx, err = app.NewLoginLoginContext(goaCtx, req, goa.New("LoginService"))

	err = s.loginService.Login(authorizeCtx, s.oauth, s.Configuration)

	locationString = rw.HeaderMap["Location"][0]
	locationUrl, err = url.Parse(locationString)
	require.Nil(s.T(), err)

	allQueryParameters = locationUrl.Query()
	assert.Equal(s.T(), 401, rw.Code) // redirect to ALM page where login was clicked.
	// Avoiding panics.
	assert.NotNil(s.T(), allQueryParameters)
	assert.NotNil(s.T(), allQueryParameters["error"])
	assert.NotEqual(s.T(), allQueryParameters["error"][0], "")

	returnedErrorReason := allQueryParameters["error"][0]
	assert.NotEmpty(s.T(), returnedErrorReason)
	assert.NotContains(s.T(), locationString, refererKeycloakUrl)
	assert.Contains(s.T(), locationString, refererUrl)
}

func (s *serviceBlackBoxTest) TestValidOAuthAuthorizationCode() {
	rw, authorizeCtx := s.loginCallback(make(map[string]string))
	s.checkLoginCallback(s.dummyOauth, rw, authorizeCtx, "token_json")
}

func (s *serviceBlackBoxTest) TestUnapprovedUserLoginUnauthorized() {
	extra := make(map[string]string)
	rw, authorizeCtx := s.loginCallback(extra)

	claims := make(map[string]interface{})
	claims["approved"] = nil
	accessToken, err := testtoken.GenerateTokenWithClaims(claims)
	require.Nil(s.T(), err)

	dummyOauth := &dummyOauth2Config{
		Config:      oauth2.Config{},
		accessToken: accessToken,
	}

	err = s.loginService.Login(authorizeCtx, dummyOauth, s.Configuration)
	require.Nil(s.T(), err)

	assert.Equal(s.T(), 401, rw.Code)

	assert.Equal(s.T(), 1, len(rw.HeaderMap["Location"]))
}

func (s *serviceBlackBoxTest) TestAPIClientForApprovedUsersReturnOK() {
	s.checkAPIClientForUsersReturnOK(true)
}

func (s *serviceBlackBoxTest) TestAPIClientForUnapprovedUsersReturnOK() {
	s.checkAPIClientForUsersReturnOK(false)
}

func (s *serviceBlackBoxTest) checkAPIClientForUsersReturnOK(approved bool) {
	extra := make(map[string]string)
	extra["api_client"] = "vscode"
	rw, authorizeCtx := s.loginCallback(extra)

	claims := make(map[string]interface{})
	if !approved {
		claims["approved"] = nil
	}
	claims["sub"] = uuid.NewV4().String()
	accessToken, err := testtoken.GenerateTokenWithClaims(claims)
	require.Nil(s.T(), err)
	refreshToken, err := testtoken.GenerateRefreshTokenWithClaims(claims)
	require.Nil(s.T(), err)

	dummyOauth := &dummyOauth2Config{
		Config:       oauth2.Config{},
		accessToken:  accessToken,
		refreshToken: refreshToken,
	}

	s.checkLoginCallback(dummyOauth, rw, authorizeCtx, "api_token")
}

func (s *serviceBlackBoxTest) TestDeprovisionedUserLoginUnauthorized() {
	extra := make(map[string]string)
	rw, authorizeCtx := s.loginCallback(extra)

	// Fails if identity is deprovisioned
	identity, err := testsupport.CreateDeprovisionedTestIdentityAndUser(s.DB, "TestDeprovisionedUserLoginUnauthorized-"+uuid.NewV4().String())
	require.NoError(s.T(), err)

	claims := make(map[string]interface{})
	claims["sub"] = identity.ID.String()
	claims["preferred_username"] = identity.Username
	claims["email"] = identity.User.Email
	accessToken, err := testtoken.GenerateTokenWithClaims(claims)
	require.Nil(s.T(), err)

	dummyOauth := &dummyOauth2Config{
		Config:      oauth2.Config{},
		accessToken: accessToken,
	}

	err = s.loginService.Login(authorizeCtx, dummyOauth, s.Configuration)
	require.NoError(s.T(), err)

	assert.Equal(s.T(), 401, rw.Code)

	assert.Equal(s.T(), 1, len(rw.HeaderMap["Location"]))
}

func (s *serviceBlackBoxTest) TestNotDeprovisionedUserLoginOK() {
	extra := make(map[string]string)
	rw, authorizeCtx := s.loginCallback(extra)

	// OK if identity is not deprovisioned
	identity, err := testsupport.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "TestDeprovisionedUserLoginUnauthorized-"+uuid.NewV4().String())
	require.NoError(s.T(), err)

	claims := make(map[string]interface{})
	claims["sub"] = identity.ID.String()
	claims["preferred_username"] = identity.Username
	claims["email"] = identity.User.Email
	accessToken, err := testtoken.GenerateTokenWithClaims(claims)
	require.Nil(s.T(), err)
	refreshToken, err := testtoken.GenerateRefreshTokenWithClaims(claims)
	require.Nil(s.T(), err)

	dummyOauth := &dummyOauth2Config{
		Config:       oauth2.Config{},
		accessToken:  accessToken,
		refreshToken: refreshToken,
	}

	err = s.loginService.Login(authorizeCtx, dummyOauth, s.Configuration)
	require.NoError(s.T(), err)

	assert.Equal(s.T(), 307, rw.Code)
}

func (s *serviceBlackBoxTest) TestExchangeRefreshTokenFailsIfInvalidToken() {
	// Fails if invalid format of refresh token
	s.keycloakTokenService.fail = false
	_, err := s.loginService.ExchangeRefreshToken(context.Background(), "", "", s.Configuration)
	require.EqualError(s.T(), err, "token contains an invalid number of segments")
	require.IsType(s.T(), autherrors.NewUnauthorizedError(""), err)

	// Fails if refresh token is expired
	identity, err := testsupport.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "TestExchangeRefreshTokenFailsIfInvalidToken-"+uuid.NewV4().String())
	require.NoError(s.T(), err)

	claims := make(map[string]interface{})
	claims["sub"] = identity.ID.String()
	claims["iat"] = time.Now().Unix() - 60*60 // Issued 1h ago
	claims["exp"] = time.Now().Unix() - 60    // Expired 1m ago
	refreshToken, err := testtoken.GenerateRefreshTokenWithClaims(claims)
	require.NoError(s.T(), err)

	ctx := testtoken.ContextWithRequest(nil)
	_, err = s.loginService.ExchangeRefreshToken(ctx, refreshToken, "", s.Configuration)
	require.EqualError(s.T(), err, "Token is expired")
	require.IsType(s.T(), autherrors.NewUnauthorizedError(""), err)

	// OK if not expired
	claims["exp"] = time.Now().Unix() + 60*60 // Expires in 1h
	refreshToken, err = testtoken.GenerateRefreshTokenWithClaims(claims)
	require.NoError(s.T(), err)

	_, err = s.loginService.ExchangeRefreshToken(ctx, refreshToken, "", s.Configuration)
	require.NoError(s.T(), err)

	// Fails if KC fails
	s.keycloakTokenService.fail = true
	_, err = s.loginService.ExchangeRefreshToken(context.Background(), refreshToken, "", s.Configuration)
	require.EqualError(s.T(), err, "kc refresh failed")
	require.IsType(s.T(), autherrors.NewUnauthorizedError(""), err)
}

func (s *serviceBlackBoxTest) TestExchangeRefreshTokenForDeprovisionedUser() {
	// 1. Fails if identity is deprovisioned
	s.keycloakTokenService.fail = false
	identity, err := testsupport.CreateDeprovisionedTestIdentityAndUser(s.DB, "TestExchangeRefreshTokenForDeprovisionedUser-"+uuid.NewV4().String())
	require.NoError(s.T(), err)

	// Refresh tokens
	ctx := testtoken.ContextWithRequest(nil)
	generatedToken, err := testtoken.TokenManager.GenerateUserTokenForIdentity(ctx, identity)
	require.NoError(s.T(), err)
	_, err = s.loginService.ExchangeRefreshToken(ctx, generatedToken.RefreshToken, "", s.Configuration)
	require.NotNil(s.T(), err)
	require.IsType(s.T(), autherrors.NewUnauthorizedError(""), err)
	require.Equal(s.T(), "unauthorized access", err.Error())

	// 2. OK if identity is not deprovisioned
	identity, err = testsupport.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "TestExchangeRefreshTokenForDeprovisionedUser-"+uuid.NewV4().String())
	require.NoError(s.T(), err)

	// Generate expected tokens returned by dummy KC service
	claims := make(map[string]interface{})
	claims["sub"] = identity.ID.String()
	accessToken, err := testtoken.GenerateAccessTokenWithClaims(claims)
	require.NoError(s.T(), err)
	refreshToken, err := testtoken.GenerateRefreshTokenWithClaims(claims)
	require.NoError(s.T(), err)
	typ := "bearer"
	var in30days int64
	in30days = 30 * 24 * 60 * 60
	s.keycloakTokenService.tokenSet = token.TokenSet{AccessToken: &accessToken, RefreshToken: &refreshToken, TokenType: &typ, ExpiresIn: &in30days, RefreshExpiresIn: &in30days}

	// Refresh tokens
	generatedToken, err = testtoken.TokenManager.GenerateUserTokenForIdentity(ctx, identity)
	require.NoError(s.T(), err)
	tokenSet, err := s.loginService.ExchangeRefreshToken(ctx, generatedToken.RefreshToken, "", s.Configuration)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), tokenSet)

	// Compare tokens
	err = testtoken.EqualAccessTokens(ctx, *s.keycloakTokenService.tokenSet.RefreshToken, *tokenSet.RefreshToken)
	require.NoError(s.T(), err)
	err = testtoken.EqualRefreshTokens(ctx, *s.keycloakTokenService.tokenSet.AccessToken, *tokenSet.AccessToken)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), typ, *tokenSet.TokenType)
	assert.Equal(s.T(), in30days, *tokenSet.ExpiresIn)
	assert.Equal(s.T(), in30days, *tokenSet.RefreshExpiresIn)
}

func (s *serviceBlackBoxTest) loginCallback(extraParams map[string]string) (*httptest.ResponseRecorder, *app.LoginLoginContext) {
	// Setup request context
	rw := httptest.NewRecorder()
	u := &url.URL{
		Host: "openshift.io",
		Path: fmt.Sprintf("/api/login"),
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	require.Nil(s.T(), err)

	prms := url.Values{}
	originalRedirect := "https://openshift.io/somepath"
	prms.Add("redirect", originalRedirect)
	for key, value := range extraParams {
		prms.Add(key, value)
	}

	ctx := context.Background()
	goaCtx := goa.NewContext(goa.WithAction(ctx, "LoginTest"), rw, req, prms)
	authorizeCtx, err := app.NewLoginLoginContext(goaCtx, req, goa.New("LoginService"))
	require.Nil(s.T(), err)

	err = s.loginService.Login(authorizeCtx, s.dummyOauth, s.Configuration)
	require.Nil(s.T(), err)

	assert.Equal(s.T(), 307, rw.Code) // redirect to keycloak login page.

	locationString := rw.HeaderMap["Location"][0]
	locationUrl, err := url.Parse(locationString)
	require.Nil(s.T(), err)

	allQueryParameters := locationUrl.Query()

	assert.NotNil(s.T(), allQueryParameters)
	assert.NotNil(s.T(), allQueryParameters["state"][0])

	returnedState := allQueryParameters["state"][0]

	prms = url.Values{
		"state": {returnedState},
		"code":  {"SOME_OAUTH2.0_CODE"},
	}
	ctx = context.Background()
	rw = httptest.NewRecorder()

	req, err = http.NewRequest("GET", u.String(), nil)
	require.Nil(s.T(), err)

	// The OAuth code is sent as a query parameter by calling /api/login?code=_SOME_CODE_&state=_SOME_STATE_
	// The request originates from Keycloak after a valid authorization by the end user.
	refererKeycloakUrl := "https://keycloak-url.example.org/path-of-login"
	req.Header.Add("referer", refererKeycloakUrl)

	goaCtx = goa.NewContext(goa.WithAction(ctx, "LoginTest"), rw, req, prms)
	authorizeCtx, err = app.NewLoginLoginContext(goaCtx, req, goa.New("LoginService"))
	require.Nil(s.T(), err)

	return rw, authorizeCtx
}

func (s *serviceBlackBoxTest) checkLoginCallback(dummyOauth *dummyOauth2Config, rw *httptest.ResponseRecorder, authorizeCtx *app.LoginLoginContext, tokenParam string) {

	err := s.loginService.Login(authorizeCtx, dummyOauth, s.Configuration)
	require.Nil(s.T(), err)

	locationString := rw.HeaderMap["Location"][0]
	locationUrl, err := url.Parse(locationString)
	require.Nil(s.T(), err)

	allQueryParameters := locationUrl.Query()

	assert.Equal(s.T(), 307, rw.Code) // redirect to the original redirect page

	assert.NotNil(s.T(), allQueryParameters)
	tokenJson := allQueryParameters[tokenParam]
	require.NotNil(s.T(), tokenJson)
	require.True(s.T(), len(tokenJson) > 0)

	tokenSet, err := token.ReadTokenSetFromJson(context.Background(), tokenJson[0])
	require.NoError(s.T(), err)

	assert.NoError(s.T(), testtoken.EqualAccessTokens(context.Background(), dummyOauth.accessToken, *tokenSet.AccessToken))
	assert.NoError(s.T(), testtoken.EqualAccessTokens(context.Background(), dummyOauth.refreshToken, *tokenSet.RefreshToken))

	assert.NotContains(s.T(), locationString, "https://keycloak-url.example.org/path-of-login")
	assert.Contains(s.T(), locationString, "https://openshift.io/somepath")
}

type dummyOauth2Config struct {
	oauth2.Config
	accessToken  string
	refreshToken string
}

func (c *dummyOauth2Config) Exchange(ctx netcontext.Context, code string) (*oauth2.Token, error) {
	var thirtyDays, nbf int64
	thirtyDays = 60 * 60 * 24 * 30
	token := &oauth2.Token{
		TokenType:    "bearer",
		AccessToken:  c.accessToken,
		RefreshToken: c.refreshToken,
		Expiry:       time.Unix(time.Now().Unix()+thirtyDays, 0),
	}
	extra := make(map[string]interface{})
	extra["expires_in"] = time.Now().Unix() + thirtyDays
	extra["refresh_expires_in"] = time.Now().Unix() + thirtyDays
	extra["not_before_policy"] = nbf
	token = token.WithExtra(extra)
	return token, nil
}

func (s *serviceBlackBoxTest) TestKeycloakAuthorizationRedirectForAuthorize() {
	rw := httptest.NewRecorder()
	u := &url.URL{
		Path: fmt.Sprintf(client.AuthorizeAuthorizePath()),
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		panic("invalid test " + err.Error()) // bug
	}

	// The user clicks login while on ALM UI.
	// Therefore the referer would be an ALM URL.
	refererUrl := "https://alm-url.example.org/path"
	req.Header.Add("referer", refererUrl)

	prms := url.Values{}

	prms.Add("response_type", "code")
	prms.Add("redirect_uri", "https://openshift.io/somepath")
	prms.Add("client_id", "740650a2-9c44-4db5-b067-a3d1b2cd2d01")
	prms.Add("state", uuid.NewV4().String())

	ctx := context.Background()
	goaCtx := goa.NewContext(goa.WithAction(ctx, "AuthorizeTest"), rw, req, prms)
	authorizeCtx, err := app.NewAuthorizeAuthorizeContext(goaCtx, req, goa.New("LoginService"))
	if err != nil {
		panic("invalid test data " + err.Error()) // bug
	}
	require.Nil(s.T(), err)

	redirectTo, err := s.loginService.AuthCodeURL(authorizeCtx, &authorizeCtx.RedirectURI, authorizeCtx.APIClient, &authorizeCtx.State, authorizeCtx.ResponseMode, authorizeCtx.RequestData, s.oauth, s.Configuration)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), redirectTo)

	prms.Add("response_mode", "fragment")
	prms.Set("state", uuid.NewV4().String())
	ctx = context.Background()
	goaCtx = goa.NewContext(goa.WithAction(ctx, "AuthorizeTest"), rw, req, prms)
	authorizeCtx, err = app.NewAuthorizeAuthorizeContext(goaCtx, req, goa.New("LoginService"))
	require.Nil(s.T(), err)
	redirectTo, err = s.loginService.AuthCodeURL(authorizeCtx, &authorizeCtx.RedirectURI, authorizeCtx.APIClient, &authorizeCtx.State, authorizeCtx.ResponseMode, authorizeCtx.RequestData, s.oauth, s.Configuration)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), redirectTo)
}

func (s *serviceBlackBoxTest) TestValidOAuthAuthorizationCodeForAuthorize() {

	_, callbackCtx := s.authorizeCallback("valid_code")
	_, err := s.loginService.AuthCodeCallback(callbackCtx)
	require.Nil(s.T(), err)

	keycloakToken, err := s.loginService.Exchange(callbackCtx, callbackCtx.Code, s.dummyOauth)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), keycloakToken)
}

func (s *serviceBlackBoxTest) TestInvalidOAuthAuthorizationCodeForAuthorize() {

	_, callbackCtx := s.authorizeCallback("invalid_code")
	_, err := s.loginService.AuthCodeCallback(callbackCtx)
	require.Nil(s.T(), err)
	ctx := context.Background()
	rw := httptest.NewRecorder()

	u := &url.URL{
		Path: fmt.Sprintf(client.ExchangeTokenPath()),
	}
	req, err := http.NewRequest("POST", u.String(), nil)
	require.Nil(s.T(), err)

	prms := url.Values{}

	// The OAuth code is sent as a query parameter by calling /api/login?code=_SOME_CODE_&state=_SOME_STATE_
	// The request originates from Keycloak after a valid authorization by the end user.
	refererKeycloakUrl := "https://keycloak-url.example.org/path-of-login"
	req.Header.Add("referer", refererKeycloakUrl)

	goaCtx := goa.NewContext(goa.WithAction(ctx, "TokenTest"), rw, req, prms)
	tokenCtx, err := app.NewExchangeTokenContext(goaCtx, req, goa.New("LoginService"))
	require.Nil(s.T(), err)
	keycloakToken, err := s.loginService.Exchange(tokenCtx, "INVALID_OAUTH2.0_CODE", s.oauth)
	require.NotNil(s.T(), err)
	require.Nil(s.T(), keycloakToken)
	jsonapi.JSONErrorResponse(tokenCtx, err)
	require.Equal(s.T(), 401, rw.Code)

}

func (s *serviceBlackBoxTest) TestInvalidOAuthStateForAuthorize() {

	rw, callbackCtx := s.authorizeCallback("invalid_state")
	_, err := s.loginService.AuthCodeCallback(callbackCtx)
	require.NotNil(s.T(), err)
	jsonapi.JSONErrorResponse(callbackCtx, err)
	assert.Equal(s.T(), 401, rw.Code)
}

func (s *serviceBlackBoxTest) authorizeCallback(testType string) (*httptest.ResponseRecorder, *app.CallbackAuthorizeContext) {
	// Setup request context
	rw := httptest.NewRecorder()
	u := &url.URL{
		Path: fmt.Sprintf(client.AuthorizeAuthorizePath()),
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	require.Nil(s.T(), err)

	prms := url.Values{}

	prms.Add("response_type", "code")
	prms.Add("redirect_uri", "https://openshift.io/somepath")
	prms.Add("client_id", "740650a2-9c44-4db5-b067-a3d1b2cd2d01")
	prms.Add("state", uuid.NewV4().String())

	ctx := context.Background()
	goaCtx := goa.NewContext(goa.WithAction(ctx, "AuthorizeTest"), rw, req, prms)
	authorizeCtx, err := app.NewAuthorizeAuthorizeContext(goaCtx, req, goa.New("LoginService"))
	require.Nil(s.T(), err)

	redirectTo, err := s.loginService.AuthCodeURL(authorizeCtx, &authorizeCtx.RedirectURI, authorizeCtx.APIClient, &authorizeCtx.State, authorizeCtx.ResponseMode, authorizeCtx.RequestData, s.dummyOauth, s.Configuration)
	require.Nil(s.T(), err)

	authorizeCtx.ResponseData.Header().Set("Cache-Control", "no-cache")
	authorizeCtx.ResponseData.Header().Set("Location", *redirectTo)

	locationString := rw.HeaderMap["Location"][0]
	locationUrl, err := url.Parse(locationString)
	require.Nil(s.T(), err)

	allQueryParameters := locationUrl.Query()

	assert.NotNil(s.T(), allQueryParameters)
	assert.NotNil(s.T(), allQueryParameters["state"][0])

	returnedState := allQueryParameters["state"][0]

	u = &url.URL{
		Path: fmt.Sprintf(client.CallbackAuthorizePath()),
	}

	if testType == "valid_code" {
		prms = url.Values{
			"state": {returnedState},
			"code":  {"SOME_OAUTH2.0_CODE"},
		}
	}

	if testType == "invalid_code" {
		prms = url.Values{
			"state": {returnedState},
			"code":  {"INVALID_OAUTH2.0_CODE"},
		}
	}

	if testType == "invalid_state" {
		prms = url.Values{
			"state": {uuid.NewV4().String()},
			"code":  {"SOME_OAUTH2.0_CODE"},
		}
	}

	ctx = context.Background()
	rw = httptest.NewRecorder()

	req, err = http.NewRequest("GET", u.String(), nil)
	require.Nil(s.T(), err)

	// The OAuth code is sent as a query parameter by calling /api/login?code=_SOME_CODE_&state=_SOME_STATE_
	// The request originates from Keycloak after a valid authorization by the end user.
	refererKeycloakUrl := "https://keycloak-url.example.org/path-of-login"
	req.Header.Add("referer", refererKeycloakUrl)

	goaCtx = goa.NewContext(goa.WithAction(ctx, "AuthorizecallbackTest"), rw, req, prms)
	callbackCtx, err := app.NewCallbackAuthorizeContext(goaCtx, req, goa.New("LoginService"))
	require.Nil(s.T(), err)

	return rw, callbackCtx
}

type DummyTokenService struct {
	tokenSet token.TokenSet
	fail     bool
}

func (s *DummyTokenService) RefreshToken(ctx context.Context, refreshTokenEndpoint string, clientID string, clientSecret string, refreshTokenString string) (*token.TokenSet, error) {
	if s.fail {
		return nil, autherrors.NewUnauthorizedError("kc refresh failed")
	}
	return &s.tokenSet, nil
}
