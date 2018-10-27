package service_test

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

	"github.com/fabric8-services/fabric8-auth/rest"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application/service/factory"
	"github.com/fabric8-services/fabric8-auth/authentication/provider"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/client"
	"github.com/fabric8-services/fabric8-auth/configuration"
	config "github.com/fabric8-services/fabric8-auth/configuration"
	autherrors "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/resource"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	testoauth "github.com/fabric8-services/fabric8-auth/test/token/oauth"

	"github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	"github.com/goadesign/goa/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	netcontext "golang.org/x/net/context"
	"golang.org/x/oauth2"
)

type authenticationProviderServiceTestSuite struct {
	gormtestsupport.DBTestSuite
	oauth                  provider.IdentityProvider
	osoSubscriptionManager *testsupport.DummyOSORegistrationApp
}

func TestAuthenticationProviderServiceBlackBox(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &authenticationProviderServiceTestSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

// SetupSuite overrides the DBTestSuite's function but calls it before doing anything else
// The SetupSuite method will run before the tests in the suite are run.
// It sets up a database connection for all the tests in this suite without polluting global space.
func (s *authenticationProviderServiceTestSuite) SetupSuite() {
	s.DBTestSuite.SetupSuite()

	s.oauth = provider.NewIdentityProvider(s.Configuration)

	claims := make(map[string]interface{})
	claims["sub"] = uuid.NewV4().String()

	s.osoSubscriptionManager = &testsupport.DummyOSORegistrationApp{}
	witServiceMock := testsupport.NewWITMock(s.T(), uuid.NewV4().String(), "test-space")
	s.Application = gormapplication.NewGormDB(s.DB, s.Configuration, factory.WithWITService(witServiceMock))
}

func (s *authenticationProviderServiceTestSuite) TestOAuthAuthorizationRedirect() {
	rw := httptest.NewRecorder()
	u := &url.URL{
		Path: fmt.Sprintf("/api/login"),
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		panic("invalid test " + err.Error()) // bug
	}

	// The user clicks login while on OSIO UI.
	// Therefore the referer would be an OSIO URL.
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

	callbackUrl := rest.AbsoluteURL(authorizeCtx.RequestData, client.CallbackLoginPath(), nil)
	generatedState := uuid.NewV4().String()
	redirectUrl, err := s.Application.AuthenticationProviderService().GenerateAuthCodeURL(ctx, authorizeCtx.Redirect, authorizeCtx.APIClient,
		&generatedState, nil, nil, refererUrl, callbackUrl)

	assert.Equal(s.T(), 307, rw.Code)
	assert.Contains(s.T(), redirectUrl, s.Configuration.GetOAuthProviderEndpointAuth())
	assert.NotEqual(s.T(), redirectUrl, "")
}

func (s *authenticationProviderServiceTestSuite) TestUnapprovedUserUnauthorized() {
	claims := make(map[string]interface{})
	claims["username"] = "something-that-doesn-not-exist-in-db" + uuid.NewV4().String()
	token, err := testtoken.GenerateTokenWithClaims(claims)
	require.Nil(s.T(), err)

	_, _, err = s.Application.AuthenticationProviderService().GetExistingIdentityInfo(context.Background(), token)
	require.NotNil(s.T(), err)
	require.IsType(s.T(), autherrors.NewUnauthorizedError(""), err)

	_, err = s.unapprovedUserRedirected()
	require.NotNil(s.T(), err)
	require.IsType(s.T(), autherrors.NewUnauthorizedError(""), err)
}

func (s *authenticationProviderServiceTestSuite) TestUnapprovedUserRedirected() {
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

func (s *authenticationProviderServiceTestSuite) unapprovedUserRedirected() (*string, error) {
	redirect, err := url.Parse("https://openshift.io/_home")
	require.Nil(s.T(), err)

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

	token := &oauth2.Token{Expiry: time.Now(), AccessToken: accessToken, RefreshToken: refreshToken}
	redirectURL, _, err := s.Application.AuthenticationProviderService().CreateOrUpdateIdentityAndUser(testtoken.ContextWithRequest(context.Background()), redirect, token)
	return redirectURL, err
}

func (s *authenticationProviderServiceTestSuite) resetConfiguration() {
	var err error
	s.Configuration, err = configuration.GetConfigurationData()
	require.Nil(s.T(), err)
}

func (s *authenticationProviderServiceTestSuite) TestOAuthAuthorizationRedirectsToRedirectParam() {
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

	callbackUrl := rest.AbsoluteURL(authorizeCtx.RequestData, client.CallbackLoginPath(), nil)
	generatedState := uuid.NewV4().String()
	redirectUrl, err := s.Application.AuthenticationProviderService().GenerateAuthCodeURL(ctx, authorizeCtx.Redirect, authorizeCtx.APIClient,
		&generatedState, nil, nil, "", callbackUrl)

	assert.Equal(s.T(), 307, rw.Code)
	assert.Contains(s.T(), redirectUrl, s.Configuration.GetOAuthProviderEndpointAuth())
	assert.NotEqual(s.T(), redirectUrl, "")
}

func (s *authenticationProviderServiceTestSuite) TestOAuthAuthorizationWithNoRefererAndRedirectParamFails() {
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

	callbackUrl := rest.AbsoluteURL(authorizeCtx.RequestData, client.CallbackLoginPath(), nil)
	generatedState := uuid.NewV4().String()
	_, err = s.Application.AuthenticationProviderService().GenerateAuthCodeURL(ctx, authorizeCtx.Redirect, authorizeCtx.APIClient,
		&generatedState, nil, nil, "", callbackUrl)

	require.Error(s.T(), err)
	require.IsType(s.T(), err, autherrors.BadParameterError{})
}

func (s *authenticationProviderServiceTestSuite) TestProviderAuthorizationWithNoValidRefererFails() {

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

	callbackUrl := rest.AbsoluteURL(authorizeCtx.RequestData, client.CallbackLoginPath(), nil)
	generatedState := uuid.NewV4().String()
	_, err = s.Application.AuthenticationProviderService().GenerateAuthCodeURL(ctx, authorizeCtx.Redirect, authorizeCtx.APIClient,
		&generatedState, nil, nil, "", callbackUrl)

	require.Error(s.T(), err)
	require.IsType(s.T(), err, autherrors.BadParameterError{})

	// openshift.io redirects pass
	rw = httptest.NewRecorder()
	prms = url.Values{}
	prms.Add("redirect", "https://openshift.io/somepath")

	goaCtx = goa.NewContext(goa.WithAction(ctx, "LoginTest"), rw, req, prms)
	authorizeCtx, err = app.NewLoginLoginContext(goaCtx, req, goa.New("LoginService"))
	if err != nil {
		panic("invalid test data " + err.Error()) // bug
	}

	generatedState = uuid.NewV4().String()
	redirectUrl, err := s.Application.AuthenticationProviderService().GenerateAuthCodeURL(ctx, authorizeCtx.Redirect, authorizeCtx.APIClient,
		&generatedState, nil, nil, "", callbackUrl)

	assert.Contains(s.T(), redirectUrl, s.Configuration.GetOAuthProviderEndpointAuth())
	assert.NotEqual(s.T(), redirectUrl, "")

	// devcluster valid referrer passes
	rw = httptest.NewRecorder()
	prms = url.Values{}
	prms.Add("redirect", "http://rhche-dfestal-preview-che.devtools-dev.ext.devshift.net/something")

	goaCtx = goa.NewContext(goa.WithAction(ctx, "LoginTest"), rw, req, prms)
	authorizeCtx, err = app.NewLoginLoginContext(goaCtx, req, goa.New("LoginService"))
	if err != nil {
		panic("invalid test data " + err.Error()) // bug
	}

	generatedState = uuid.NewV4().String()
	redirectUrl, err = s.Application.AuthenticationProviderService().GenerateAuthCodeURL(ctx, authorizeCtx.Redirect, authorizeCtx.APIClient,
		&generatedState, nil, nil, "", callbackUrl)

	assert.Equal(s.T(), 307, rw.Code)
	assert.Contains(s.T(), redirectUrl, s.Configuration.GetOAuthProviderEndpointAuth())
	assert.NotEqual(s.T(), redirectUrl, "")

}
func (s *authenticationProviderServiceTestSuite) TestOAuthAuthorizationDevModePasses() {
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

	callbackUrl := rest.AbsoluteURL(authorizeCtx.RequestData, client.CallbackLoginPath(), nil)
	generatedState := uuid.NewV4().String()
	redirectUrl, err := s.Application.AuthenticationProviderService().GenerateAuthCodeURL(ctx, authorizeCtx.Redirect, authorizeCtx.APIClient,
		&generatedState, nil, nil, "", callbackUrl)

	assert.Contains(s.T(), redirectUrl, s.Configuration.GetOAuthProviderEndpointAuth())
	assert.NotEqual(s.T(), redirectUrl, "")
}

func (s *authenticationProviderServiceTestSuite) TestInvalidState() {
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
	// The request originates from the OAuth provider after a valid authorization by the end user.
	// This is not where the redirection should happen on failure.
	refererOAuthUrl := "https://oauth-url.example.org/path-of-login"
	req.Header.Add("referer", refererOAuthUrl)

	prms := url.Values{
		"state": {},
		"code":  {"doesnt_matter_what_is_here"},
	}
	ctx := context.Background()
	goaCtx := goa.NewContext(goa.WithAction(ctx, "LoginTest"), rw, req, prms)
	authorizeCtx, err := app.NewLoginLoginContext(goaCtx, req, goa.New("LoginService"))
	require.Nil(s.T(), err)

	callbackUrl := rest.AbsoluteURL(authorizeCtx.RequestData, client.CallbackLoginPath(), nil)
	generatedState := uuid.NewV4().String()
	_, err = s.Application.AuthenticationProviderService().GenerateAuthCodeURL(ctx, authorizeCtx.Redirect, authorizeCtx.APIClient,
		&generatedState, nil, nil, "", callbackUrl)

	require.Error(s.T(), err)
	assert.Equal(s.T(), 401, rw.Code)
}

func (s *authenticationProviderServiceTestSuite) TestInvalidOAuthAuthorizationCode() {

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

	callbackUrl := rest.AbsoluteURL(authorizeCtx.RequestData, client.CallbackLoginPath(), nil)
	generatedState := uuid.NewV4().String()
	redirectUrl, err := s.Application.AuthenticationProviderService().GenerateAuthCodeURL(ctx, authorizeCtx.Redirect, authorizeCtx.APIClient,
		&generatedState, nil, nil, refererUrl, callbackUrl)

	assert.Equal(s.T(), 307, rw.Code) // redirect to oauth provider login page.

	locationUrl, err := url.Parse(*redirectUrl)
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
	// The request originates from the OAuth provider after a valid authorization by the end user.
	// This is not where the redirection should happen on failure.
	refererOAuthUrl := "https://oauth-url.example.org/path-of-login"
	req.Header.Add("referer", refererOAuthUrl)
	require.Nil(s.T(), err)

	goaCtx = goa.NewContext(goa.WithAction(ctx, "LoginTest"), rw, req, prms)
	callbackCtx, err := app.NewCallbackLoginContext(goaCtx, req, goa.New("LoginService"))

	redirectUrl, err = s.Application.AuthenticationProviderService().LoginCallback(ctx, *callbackCtx.State, *callbackCtx.Code)

	locationUrl, err = url.Parse(*redirectUrl)
	require.Nil(s.T(), err)

	allQueryParameters = locationUrl.Query()
	assert.Equal(s.T(), 401, rw.Code) // redirect to page where login was clicked.
	// Avoiding panics.
	assert.NotNil(s.T(), allQueryParameters)
	assert.NotNil(s.T(), allQueryParameters["error"])
	assert.NotEqual(s.T(), allQueryParameters["error"][0], "")

	returnedErrorReason := allQueryParameters["error"][0]
	assert.NotEmpty(s.T(), returnedErrorReason)
	assert.NotContains(s.T(), redirectUrl, refererOAuthUrl)
	assert.Contains(s.T(), redirectUrl, refererUrl)
}

func (s *authenticationProviderServiceTestSuite) getDummyOauthIDPService(forApprovedUser bool) *dummyIDPOauthService {
	g := s.NewTestGraph(s.T())
	newIdentity := g.CreateUser().Identity()
	claims := make(map[string]interface{})
	claims["sub"] = uuid.NewV4()
	if forApprovedUser {
		claims["preferred_username"] = newIdentity.Username
		claims["email"] = newIdentity.User.Email
		claims["company"] = newIdentity.User.Company
	}
	accessToken, err := testtoken.GenerateTokenWithClaims(claims)
	require.Nil(s.T(), err)

	refreshToken, err := testtoken.GenerateRefreshTokenWithClaims(claims)
	require.Nil(s.T(), err)

	dummyOauth := &dummyIDPOauthService{
		IdentityProvider: provider.NewIdentityProvider(s.Configuration),
		accessToken:      accessToken,
		refreshToken:     refreshToken,
	}
	return dummyOauth
}

func (s *authenticationProviderServiceTestSuite) TestValidOAuthAuthorizationCode() {
	rw, authorizeCtx := s.loginCallback(make(map[string]string))
	dummyOauth := s.getDummyOauthIDPService(true)
	s.checkLoginCallback(dummyOauth, rw, authorizeCtx, "token_json")
}

func (s *authenticationProviderServiceTestSuite) TestUnapprovedUserLoginUnauthorized() {
	extra := make(map[string]string)
	_, callbackCtx := s.loginCallback(extra)

	_, err := s.Application.AuthenticationProviderService().LoginCallback(s.Ctx, *callbackCtx.State, *callbackCtx.Code)
	require.Error(s.T(), err)
}

func (s *authenticationProviderServiceTestSuite) TestAPIClientForApprovedUsersReturnOK() {
	s.checkAPIClientForUsersReturnOK(true)
}

func (s *authenticationProviderServiceTestSuite) TestAPIClientForUnapprovedUsersReturnOK() {
	s.checkAPIClientForUsersReturnOK(false)
}

type dummyIDPOauth interface {
	Exchange(ctx netcontext.Context, code string) (*oauth2.Token, error)
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Profile(ctx context.Context, token oauth2.Token) (*provider.UserProfile, error)
}

type dummyIDPOauthService struct {
	provider.IdentityProvider
	accessToken  string
	refreshToken string
}

func (c *dummyIDPOauthService) Exchange(ctx netcontext.Context, code string) (*oauth2.Token, error) {
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

func (c *dummyIDPOauthService) Profile(ctx context.Context, jwtToken oauth2.Token) (*provider.UserProfile, error) {
	jwt, _ := testtoken.TokenManager.ParseToken(ctx, jwtToken.AccessToken)
	return &provider.UserProfile{
		Company:    jwt.Company,
		Subject:    jwt.Subject,
		GivenName:  "Test",
		FamilyName: "User",
		Username:   jwt.Username,
		Email:      jwt.Email,
	}, nil
}

func (s *authenticationProviderServiceTestSuite) checkAPIClientForUsersReturnOK(approved bool) {
	extra := make(map[string]string)
	extra["api_client"] = "vscode"
	rw, authorizeCtx := s.loginCallback(extra)

	dummyIDPOauthServiceRef := s.getDummyOauthIDPService(false)
	s.checkLoginCallback(dummyIDPOauthServiceRef, rw, authorizeCtx, "api_token")
}

func (s *authenticationProviderServiceTestSuite) TestDeprovisionedUserLoginUnauthorized() {
	extra := make(map[string]string)
	_, callbackCtx := s.loginCallback(extra)

	// Fails if identity is deprovisioned
	_, err := testsupport.CreateDeprovisionedTestIdentityAndUser(s.DB, "TestDeprovisionedUserLoginUnauthorized-"+uuid.NewV4().String())
	require.NoError(s.T(), err)

	redirectUrl, err := s.Application.AuthenticationProviderService().LoginCallback(callbackCtx, *callbackCtx.State, *callbackCtx.Code)

	require.NoError(s.T(), err)
	require.NotEmpty(s.T(), redirectUrl)
}

func (s *authenticationProviderServiceTestSuite) TestNotDeprovisionedUserLoginOK() {
	extra := make(map[string]string)
	_, callbackCtx := s.loginCallback(extra)

	// OK if identity is not deprovisioned
	_, err := testsupport.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "TestDeprovisionedUserLoginUnauthorized-"+uuid.NewV4().String())
	require.NoError(s.T(), err)

	_, err = s.Application.AuthenticationProviderService().LoginCallback(callbackCtx, *callbackCtx.State, *callbackCtx.Code)
	require.NoError(s.T(), err)
}

func (s *authenticationProviderServiceTestSuite) TestExchangeRefreshToken() {

	tm, err := manager.NewTokenManager(s.Configuration)
	require.NoError(s.T(), err)

	s.T().Run("valid refresh token", func(t *testing.T) {

		t.Run("without access token", func(t *testing.T) { // just expect a regular access token
			// given
			g := s.NewTestGraph(t)
			user := g.CreateUser()
			claims := make(map[string]interface{})
			claims["sub"] = user.IdentityID().String()
			claims["iat"] = time.Now().Unix() - 60*60 // Issued 1h ago
			claims["exp"] = time.Now().Unix() + 60*60 // Expires in 1h
			refreshToken, err := testtoken.GenerateRefreshTokenWithClaims(claims)
			require.NoError(t, err)
			// when
			ctx := manager.ContextWithTokenManager(testtoken.ContextWithRequest(nil), tm)
			result, err := s.Application.TokenService().ExchangeRefreshToken(ctx, "", refreshToken)
			// then
			require.NoError(t, err)
			require.NotNil(t, result)
			// verify that the refresh token is valid
			require.NotNil(t, result.RefreshToken)
			_, err = jwt.Parse(*result.RefreshToken, tm.KeyFunction(ctx))
			assert.NoError(t, err)
			// verify that the access token is valid
			require.NotNil(t, result.AccessToken)
			_, err = jwt.Parse(*result.AccessToken, tm.KeyFunction(ctx))
			assert.NoError(t, err)
		})

		t.Run("with access token", func(t *testing.T) { // just expect a regular access token
			// given
			g := s.NewTestGraph(t)
			user := g.CreateUser()
			ctx := manager.ContextWithTokenManager(testtoken.ContextWithRequest(nil), tm)
			claims := make(map[string]interface{})
			claims["sub"] = user.IdentityID().String()
			claims["iat"] = time.Now().Unix() - 60*60 // Issued 1h ago
			claims["exp"] = time.Now().Unix() + 60*60 // Expires in 1h
			refreshToken, err := testtoken.GenerateRefreshTokenWithClaims(claims)
			require.NoError(t, err)
			accessToken, err := testtoken.GenerateAccessTokenWithClaims(claims)
			require.NoError(t, err)
			// when
			result, err := s.Application.TokenService().ExchangeRefreshToken(ctx, accessToken, refreshToken)
			// then
			require.NoError(t, err)
			require.NotNil(t, result)
			// verify that the refresh token is valid
			require.NotNil(t, result.RefreshToken)
			_, err = jwt.Parse(*result.RefreshToken, tm.KeyFunction(ctx))
			assert.NoError(t, err)
			// verify that the access token is valid
			resultAccessToken, err := jwt.Parse(*result.AccessToken, tm.KeyFunction(ctx))
			require.NoError(t, err)
			resultAccessTokenClaims := resultAccessToken.Claims.(jwt.MapClaims)
			require.Nil(t, resultAccessTokenClaims["permissions"])
		})

		t.Run("with rpt token", func(t *testing.T) { // just expect a regular access token
			// given
			g := s.NewTestGraph(t)
			user := g.CreateUser()
			ctx := manager.ContextWithTokenManager(testtoken.ContextWithRequest(nil), tm)
			claims := make(map[string]interface{})
			claims["sub"] = user.IdentityID().String()
			claims["iat"] = time.Now().Unix() - 60*60 // Issued 1h ago
			claims["exp"] = time.Now().Unix() + 60*60 // Expires in 1h
			refreshToken, err := testtoken.GenerateRefreshTokenWithClaims(claims)
			require.NoError(t, err)
			accessToken, err := testtoken.GenerateAccessTokenWithClaims(claims)
			require.NoError(t, err)
			// obtain an RPT token using the access token
			space := g.CreateSpace().AddAdmin(user)
			rpt, err := s.Application.TokenService().Audit(ctx, user.Identity(), accessToken, space.SpaceID())
			require.NoError(t, err)
			// when
			result, err := s.Application.TokenService().ExchangeRefreshToken(ctx, *rpt, refreshToken)
			// then
			require.NoError(t, err)
			require.NotNil(t, result)
			// verify that the refresh token is valid
			require.NotNil(t, result.RefreshToken)
			_, err = jwt.Parse(*result.RefreshToken, tm.KeyFunction(ctx))
			require.NoError(t, err)
			// verify that the access token is valid
			require.NotNil(t, result.AccessToken)
			resultAccessToken, err := jwt.Parse(*result.AccessToken, tm.KeyFunction(ctx))
			require.NoError(t, err)
			resultAccessTokenClaims := resultAccessToken.Claims.(jwt.MapClaims)
			require.NotNil(t, resultAccessTokenClaims["permissions"])
		})

	})

	s.T().Run("fail", func(t *testing.T) {

		t.Run("invalid format", func(t *testing.T) { // Fails if invalid format of refresh token
			// given
			ctx := manager.ContextWithTokenManager(testtoken.ContextWithRequest(nil), tm)
			// when
			_, err := s.Application.TokenService().ExchangeRefreshToken(ctx, "", "")
			// then
			require.EqualError(t, err, "token contains an invalid number of segments")
			require.IsType(t, autherrors.NewUnauthorizedError(""), err)
		})

		t.Run("expired", func(t *testing.T) { // Fails if refresh token is expired
			// given
			g := s.NewTestGraph(t)
			user := g.CreateUser()
			claims := make(map[string]interface{})
			claims["sub"] = user.IdentityID().String()
			claims["iat"] = time.Now().Unix() - 60*60 // Issued 1h ago
			claims["exp"] = time.Now().Unix() - 60    // Expired 1m ago
			refreshToken, err := testtoken.GenerateRefreshTokenWithClaims(claims)
			require.NoError(t, err)
			// when
			ctx := manager.ContextWithTokenManager(testtoken.ContextWithRequest(nil), tm)
			_, err = s.Application.TokenService().ExchangeRefreshToken(ctx, "", refreshToken)
			// then
			require.EqualError(t, err, "Token is expired")
			require.IsType(t, autherrors.NewUnauthorizedError(""), err)
		})

	})

}

func (s *authenticationProviderServiceTestSuite) loginCallback(extraParams map[string]string) (*httptest.ResponseRecorder, *app.CallbackLoginContext) {
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
	require.NoError(s.T(), err)

	callbackUrl := rest.AbsoluteURL(authorizeCtx.RequestData, client.CallbackLoginPath(), nil)
	generatedState := uuid.NewV4().String()
	redirectUrl, err := s.Application.AuthenticationProviderService().GenerateAuthCodeURL(ctx, authorizeCtx.Redirect, authorizeCtx.APIClient,
		&generatedState, nil, nil, "", callbackUrl)

	require.NoError(s.T(), err)

	locationUrl, err := url.Parse(*redirectUrl)
	require.NoError(s.T(), err)

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
	require.NoError(s.T(), err)

	// The OAuth code is sent as a query parameter by calling /api/login?code=_SOME_CODE_&state=_SOME_STATE_
	// The request originates from the oauth provider after a valid authorization by the end user.
	refererOAuthUrl := "https://oauth-url.example.org/path-of-login"
	req.Header.Add("referer", refererOAuthUrl)

	goaCtx = goa.NewContext(goa.WithAction(ctx, "LoginTest"), rw, req, prms)
	loginCallbackCtx, err := app.NewCallbackLoginContext(goaCtx, req, goa.New("LoginService"))
	require.NoError(s.T(), err)

	return rw, loginCallbackCtx
}

func (s *authenticationProviderServiceTestSuite) checkLoginCallback(dummyOauth *dummyIDPOauthService, rw *httptest.ResponseRecorder, callbackCtx *app.CallbackLoginContext, tokenParam string) {

	testsupport.ActivateDummyIdentityProviderFactory(s, dummyOauth)
	redirectUrl, err := s.Application.AuthenticationProviderService().LoginCallback(s.Ctx, *callbackCtx.State, *callbackCtx.Code)
	require.Nil(s.T(), err)

	locationUrl, err := url.Parse(*redirectUrl)
	require.Nil(s.T(), err)

	allQueryParameters := locationUrl.Query()

	assert.NotNil(s.T(), allQueryParameters)
	tokenJson := allQueryParameters[tokenParam]
	require.NotNil(s.T(), tokenJson)
	require.True(s.T(), len(tokenJson) > 0)

	_, err = manager.ReadTokenSetFromJson(context.Background(), tokenJson[0])
	require.NoError(s.T(), err)

	//assert.NoError(s.T(), testtoken.EqualAccessTokens(context.Background(), dummyOauth.accessToken, *tokenSet.AccessToken))
	//assert.NoError(s.T(), testtoken.EqualRefreshTokens(context.Background(), dummyOauth.refreshToken, *tokenSet.RefreshToken))

	assert.NotContains(s.T(), *redirectUrl, "https://oauth-url.example.org/path-of-login")
	assert.Contains(s.T(), *redirectUrl, "https://openshift.io/somepath")
}

type dummyOauth2Config struct {
	oauth2.Config
	accessToken  string
	refreshToken string
}

const thirtyDays = 60 * 60 * 24 * 30

func (c *dummyOauth2Config) Exchange(ctx netcontext.Context, code string) (*oauth2.Token, error) {
	var thirtyDays, nbf int64
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

func (s *authenticationProviderServiceTestSuite) TestOAuthAuthorizationRedirectForAuthorize() {
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

	redirectTo, err := s.Application.AuthenticationProviderService().GenerateAuthCodeURL(authorizeCtx, &authorizeCtx.RedirectURI, authorizeCtx.APIClient, &authorizeCtx.State, nil, authorizeCtx.ResponseMode, refererUrl, "")
	require.Nil(s.T(), err)
	require.NotNil(s.T(), redirectTo)

	prms.Add("response_mode", "fragment")
	prms.Set("state", uuid.NewV4().String())
	ctx = context.Background()
	goaCtx = goa.NewContext(goa.WithAction(ctx, "AuthorizeTest"), rw, req, prms)
	authorizeCtx, err = app.NewAuthorizeAuthorizeContext(goaCtx, req, goa.New("LoginService"))
	require.Nil(s.T(), err)
	redirectTo, err = s.Application.AuthenticationProviderService().GenerateAuthCodeURL(authorizeCtx, &authorizeCtx.RedirectURI, authorizeCtx.APIClient, &authorizeCtx.State, nil, authorizeCtx.ResponseMode, refererUrl, "")
	require.Nil(s.T(), err)
	require.NotNil(s.T(), redirectTo)
}

func (s *authenticationProviderServiceTestSuite) TestValidOAuthAuthorizationCodeForAuthorize() {

	_, callbackCtx := s.authorizeCallback("valid_code")
	_, err := s.Application.AuthenticationProviderService().LoginCallback(callbackCtx, callbackCtx.State, callbackCtx.Code)
	require.Nil(s.T(), err)

	userToken, err := s.Application.AuthenticationProviderService().ExchangeCodeWithProvider(callbackCtx, callbackCtx.Code)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), userToken)
}

func (s *authenticationProviderServiceTestSuite) TestInvalidOAuthAuthorizationCodeForAuthorize() {

	_, callbackCtx := s.authorizeCallback("invalid_code")
	_, err := s.Application.AuthenticationProviderService().LoginCallback(callbackCtx, "", "")
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
	// The request originates from the OAuth provider after a valid authorization by the end user.
	refererOAuthUrl := "https://oauth-url.example.org/path-of-login"
	req.Header.Add("referer", refererOAuthUrl)

	goaCtx := goa.NewContext(goa.WithAction(ctx, "TokenTest"), rw, req, prms)
	tokenCtx, err := app.NewExchangeTokenContext(goaCtx, req, goa.New("LoginService"))
	require.Nil(s.T(), err)
	userToken, err := s.Application.AuthenticationProviderService().ExchangeCodeWithProvider(tokenCtx, "INVALID_OAUTH2.0_CODE")
	require.NotNil(s.T(), err)
	require.Nil(s.T(), userToken)
	jsonapi.JSONErrorResponse(tokenCtx, err)
	require.Equal(s.T(), 401, rw.Code)

}

func (s *authenticationProviderServiceTestSuite) TestInvalidOAuthStateForAuthorize() {

	rw, callbackCtx := s.authorizeCallback("invalid_state")
	_, err := s.Application.AuthenticationProviderService().LoginCallback(callbackCtx, "invalid_state", "")
	require.NotNil(s.T(), err)
	jsonapi.JSONErrorResponse(callbackCtx, err)
	assert.Equal(s.T(), 401, rw.Code)
}

func (s *authenticationProviderServiceTestSuite) TestCreateOrUpdateIdentityAndUserOK() {
	// given
	g := s.NewTestGraph(s.T())
	redirectURL := "redirect_url"
	claims := make(map[string]interface{})
	user := g.CreateUser()
	claims["sub"] = user.IdentityID().String()
	accessToken, err := testtoken.GenerateAccessTokenWithClaims(claims)
	require.NoError(s.T(), err)
	refreshToken, err := testtoken.GenerateRefreshTokenWithClaims(claims)
	require.NoError(s.T(), err)

	oauth2Token := &oauth2.Token{
		TokenType:    "bearer",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Expiry:       time.Unix(time.Now().Unix()+thirtyDays, 0),
	}
	identityProvider := testoauth.NewIdentityProviderMock(s.T())
	identityProvider.ProfileFunc = func(ctx context.Context, tk oauth2.Token) (*provider.UserProfile, error) {
		return &provider.UserProfile{
			Username: user.Identity().Username,
		}, nil
	}
	// when
	resultURL, userToken, err := s.Application.AuthenticationProviderService().CreateOrUpdateIdentityAndUser(
		testtoken.ContextWithRequest(context.Background()),
		&url.URL{Path: redirectURL},
		oauth2Token)

	// then
	require.NoError(s.T(), err)
	assert.NotNil(s.T(), resultURL)
	require.NotNil(s.T(), userToken)
	resultAccessTokenClaims, err := testtoken.TokenManager.ParseToken(context.Background(), userToken.AccessToken)
	require.NoError(s.T(), err)
	assert.NotEmpty(s.T(), resultAccessTokenClaims.SessionState)
	s.T().Logf("token claim `session_state`: %v", resultAccessTokenClaims.SessionState)

}

func (s *authenticationProviderServiceTestSuite) authorizeCallback(testType string) (*httptest.ResponseRecorder, *app.CallbackAuthorizeContext) {
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

	redirectTo, err := s.Application.AuthenticationProviderService().GenerateAuthCodeURL(authorizeCtx,
		&authorizeCtx.RedirectURI, authorizeCtx.APIClient, &authorizeCtx.State, nil, authorizeCtx.ResponseMode,
		"https://openshift.io/somepath", "")
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
	// The request originates from the OAuth provider after a valid authorization by the end user.
	refererOAuthUrl := "https://oauth-url.example.org/path-of-login"
	req.Header.Add("referer", refererOAuthUrl)

	goaCtx = goa.NewContext(goa.WithAction(ctx, "AuthorizecallbackTest"), rw, req, prms)
	callbackCtx, err := app.NewCallbackAuthorizeContext(goaCtx, req, goa.New("LoginService"))
	require.Nil(s.T(), err)

	return rw, callbackCtx
}
