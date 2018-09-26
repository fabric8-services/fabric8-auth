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

	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/token/oauth"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application/service/factory"
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

type serviceBlackBoxTestSuite struct {
	gormtestsupport.DBTestSuite
	loginService           *login.KeycloakOAuthProvider
	oauth                  oauth.IdentityProvider
	keycloakTokenService   *DummyTokenService
	osoSubscriptionManager *testsupport.DummyOSORegistrationApp
}

func TestServiceBlackBox(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &serviceBlackBoxTestSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

// SetupSuite overrides the DBTestSuite's function but calls it before doing anything else
// The SetupSuite method will run before the tests in the suite are run.
// It sets up a database connection for all the tests in this suite without polluting global space.
func (s *serviceBlackBoxTestSuite) SetupSuite() {
	s.DBTestSuite.SetupSuite()

	var err error
	s.oauth = login.NewIdentityProvider(s.Configuration)

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

	userRepository := account.NewUserRepository(s.DB)
	identityRepository := account.NewIdentityRepository(s.DB)
	userProfileClient := login.NewKeycloakUserProfileClient()

	refreshTokenSet := token.TokenSet{AccessToken: &accessToken, RefreshToken: &refreshToken}
	s.keycloakTokenService = &DummyTokenService{tokenSet: refreshTokenSet}
	s.osoSubscriptionManager = &testsupport.DummyOSORegistrationApp{}
	witServiceMock := testsupport.NewWITMock(s.T(), uuid.NewV4().String(), "test-space")
	s.Application = gormapplication.NewGormDB(s.DB, s.Configuration, factory.WithWITService(witServiceMock))
	s.loginService = login.NewKeycloakOAuthProvider(identityRepository, userRepository, testtoken.TokenManager, s.Application, userProfileClient, s.keycloakTokenService, s.osoSubscriptionManager)
}

func (s *serviceBlackBoxTestSuite) TestKeycloakAuthorizationRedirect() {
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
	assert.Contains(s.T(), rw.Header().Get("Location"), s.Configuration.GetOAuthEndpointAuth())
	assert.NotEqual(s.T(), rw.Header().Get("Location"), "")
}

func (s *serviceBlackBoxTestSuite) TestUnapprovedUserUnauthorized() {
	claims := make(map[string]interface{})
	claims["username"] = "something-that-doesn-not-exist-in-db" + uuid.NewV4().String()
	token, err := testtoken.GenerateTokenWithClaims(claims)
	require.Nil(s.T(), err)

	dummyOauthIDPRef := s.getDummyOauthIDPService(true)

	_, _, err = s.loginService.CreateOrUpdateIdentityInDB(context.Background(), token, dummyOauthIDPRef, s.Configuration)
	require.NotNil(s.T(), err)
	require.IsType(s.T(), autherrors.NewUnauthorizedError(""), err)

	_, err = s.unapprovedUserRedirected()
	require.NotNil(s.T(), err)
	require.IsType(s.T(), autherrors.NewUnauthorizedError(""), err)
}

func (s *serviceBlackBoxTestSuite) TestUnapprovedUserRedirected() {
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

func (s *serviceBlackBoxTestSuite) unapprovedUserRedirected() (*string, error) {
	redirect, err := url.Parse("https://openshift.io/_home")
	require.Nil(s.T(), err)

	req := &goa.RequestData{
		Request: &http.Request{Host: "auth.openshift.io"},
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

	token := &oauth2.Token{Expiry: time.Now(), AccessToken: accessToken, RefreshToken: refreshToken}
	dummyOauth := s.getDummyOauthIDPService(false)
	redirectURL, _, err := s.loginService.CreateOrUpdateIdentityAndUser(testtoken.ContextWithRequest(context.Background()), redirect, token, req, dummyOauth, s.Configuration)
	return redirectURL, err
}

func (s *serviceBlackBoxTestSuite) resetConfiguration() {
	var err error
	s.Configuration, err = configuration.GetConfigurationData()
	require.Nil(s.T(), err)
}

func (s *serviceBlackBoxTestSuite) TestKeycloakAuthorizationRedirectsToRedirectParam() {
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
	assert.Contains(s.T(), rw.Header().Get("Location"), s.Configuration.GetOAuthEndpointAuth())
	assert.NotEqual(s.T(), rw.Header().Get("Location"), "")
}

func (s *serviceBlackBoxTestSuite) TestKeycloakAuthorizationWithNoRefererAndRedirectParamFails() {
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

func (s *serviceBlackBoxTestSuite) TestKeycloakAuthorizationWithNoValidRefererFails() {

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
	assert.Contains(s.T(), rw.Header().Get("Location"), s.Configuration.GetOAuthEndpointAuth())
	assert.NotEqual(s.T(), rw.Header().Get("Location"), "")

	// devcluster valid referrer passes
	rw = httptest.NewRecorder()
	prms = url.Values{}
	prms.Add("redirect", "http://rhche-dfestal-preview-che.devtools-dev.ext.devshift.net/something")

	goaCtx = goa.NewContext(goa.WithAction(ctx, "LoginTest"), rw, req, prms)
	authorizeCtx, err = app.NewLoginLoginContext(goaCtx, req, goa.New("LoginService"))
	if err != nil {
		panic("invalid test data " + err.Error()) // bug
	}

	err = s.loginService.Login(authorizeCtx, s.oauth, s.Configuration)
	assert.Equal(s.T(), 307, rw.Code)
	assert.Contains(s.T(), rw.Header().Get("Location"), s.Configuration.GetOAuthEndpointAuth())
	assert.NotEqual(s.T(), rw.Header().Get("Location"), "")

}
func (s *serviceBlackBoxTestSuite) TestKeycloakAuthorizationDevModePasses() {
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
	assert.Contains(s.T(), rw.Header().Get("Location"), s.Configuration.GetOAuthEndpointAuth())
	assert.NotEqual(s.T(), rw.Header().Get("Location"), "")
}

func (s *serviceBlackBoxTestSuite) TestInvalidState() {
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

func (s *serviceBlackBoxTestSuite) TestInvalidOAuthAuthorizationCode() {

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

func (s *serviceBlackBoxTestSuite) getDummyOauthIDPService(forApprovedUser bool) *dummyIDPOauthService {
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
		IdentityProvider: *login.NewIdentityProvider(s.Configuration),
		accessToken:      accessToken,
		refreshToken:     refreshToken,
	}
	return dummyOauth
}

func (s *serviceBlackBoxTestSuite) TestValidOAuthAuthorizationCode() {
	rw, authorizeCtx := s.loginCallback(make(map[string]string))
	dummyOauth := s.getDummyOauthIDPService(true)
	s.checkLoginCallback(dummyOauth, rw, authorizeCtx, "token_json")
}

func (s *serviceBlackBoxTestSuite) TestUnapprovedUserLoginUnauthorized() {
	extra := make(map[string]string)
	rw, authorizeCtx := s.loginCallback(extra)

	dummyOauth := s.getDummyOauthIDPService(false)

	err := s.loginService.Login(authorizeCtx, dummyOauth, s.Configuration)
	require.Nil(s.T(), err)

	assert.Equal(s.T(), 401, rw.Code)

	assert.Equal(s.T(), 1, len(rw.HeaderMap["Location"]))
}

func (s *serviceBlackBoxTestSuite) TestAPIClientForApprovedUsersReturnOK() {
	s.checkAPIClientForUsersReturnOK(true)
}

func (s *serviceBlackBoxTestSuite) TestAPIClientForUnapprovedUsersReturnOK() {
	s.checkAPIClientForUsersReturnOK(false)
}

type dummyIDPOauth interface {
	Exchange(ctx netcontext.Context, code string) (*oauth2.Token, error)
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Profile(ctx context.Context, token oauth2.Token) (*oauth.UserProfile, error)
}

type dummyIDPOauthService struct {
	login.IdentityProvider
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

func (c *dummyIDPOauthService) Profile(ctx context.Context, jwtToken oauth2.Token) (*oauth.UserProfile, error) {
	jwt, _ := testtoken.TokenManager.ParseToken(ctx, jwtToken.AccessToken)
	return &oauth.UserProfile{
		Company:    jwt.Company,
		Subject:    jwt.Subject,
		GivenName:  "Test",
		FamilyName: "User",
		Username:   jwt.Username,
		Email:      jwt.Email,
	}, nil
}

func (s *serviceBlackBoxTestSuite) checkAPIClientForUsersReturnOK(approved bool) {
	extra := make(map[string]string)
	extra["api_client"] = "vscode"
	rw, authorizeCtx := s.loginCallback(extra)

	dummyIDPOauthServiceRef := s.getDummyOauthIDPService(false)
	s.checkLoginCallback(dummyIDPOauthServiceRef, rw, authorizeCtx, "api_token")
}

func (s *serviceBlackBoxTestSuite) TestDeprovisionedUserLoginUnauthorized() {
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

	dummyOauth := &dummyIDPOauthService{
		IdentityProvider: *login.NewIdentityProvider(s.Configuration),
		accessToken:      accessToken,
	}

	err = s.loginService.Login(authorizeCtx, dummyOauth, s.Configuration)
	require.NoError(s.T(), err)

	assert.Equal(s.T(), 401, rw.Code)

	assert.Equal(s.T(), 1, len(rw.HeaderMap["Location"]))
}

func (s *serviceBlackBoxTestSuite) TestNotDeprovisionedUserLoginOK() {
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

	dummyIDPConfigRef := dummyIDPOauthService{
		IdentityProvider: *login.NewIdentityProvider(s.Configuration),
		accessToken:      accessToken,
		refreshToken:     refreshToken,
	}

	err = s.loginService.Login(authorizeCtx, &dummyIDPConfigRef, s.Configuration)
	require.NoError(s.T(), err)

	assert.Equal(s.T(), 307, rw.Code)
}

func (s *serviceBlackBoxTestSuite) TestExchangeRefreshTokenFailsIfInvalidToken() {
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

func (s *serviceBlackBoxTestSuite) TestExchangeRefreshTokenForDeprovisionedUser() {
	// 1. Fails if identity is deprovisioned
	s.keycloakTokenService.fail = false
	identity, err := testsupport.CreateDeprovisionedTestIdentityAndUser(s.DB, "TestExchangeRefreshTokenForDeprovisionedUser-"+uuid.NewV4().String())
	require.NoError(s.T(), err)

	// Refresh tokens
	ctx := testtoken.ContextWithRequest(nil)
	generatedToken, err := testtoken.TokenManager.GenerateUserTokenForIdentity(ctx, identity, false)
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
	generatedToken, err = testtoken.TokenManager.GenerateUserTokenForIdentity(ctx, identity, false)
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
	// verify some claims in the resulting access tokens
	assert.NotNil(s.T(), tokenSet.AccessToken)
	accessClaims, err := testtoken.TokenManager.ParseToken(ctx, *tokenSet.AccessToken)
	assert.NotEmpty(s.T(), accessClaims.SessionState)

}

func (s *serviceBlackBoxTestSuite) loginCallback(extraParams map[string]string) (*httptest.ResponseRecorder, *app.LoginLoginContext) {
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

	dummyOauth := s.getDummyOauthIDPService(false)
	err = s.loginService.Login(authorizeCtx, dummyOauth, s.Configuration)
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

func (s *serviceBlackBoxTestSuite) checkLoginCallback(dummyOauth *dummyIDPOauthService, rw *httptest.ResponseRecorder, authorizeCtx *app.LoginLoginContext, tokenParam string) {

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

	_, err = token.ReadTokenSetFromJson(context.Background(), tokenJson[0])
	require.NoError(s.T(), err)

	//assert.NoError(s.T(), testtoken.EqualAccessTokens(context.Background(), dummyOauth.accessToken, *tokenSet.AccessToken))
	//assert.NoError(s.T(), testtoken.EqualRefreshTokens(context.Background(), dummyOauth.refreshToken, *tokenSet.RefreshToken))

	assert.NotContains(s.T(), locationString, "https://keycloak-url.example.org/path-of-login")
	assert.Contains(s.T(), locationString, "https://openshift.io/somepath")
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

func (s *serviceBlackBoxTestSuite) TestKeycloakAuthorizationRedirectForAuthorize() {
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

func (s *serviceBlackBoxTestSuite) TestValidOAuthAuthorizationCodeForAuthorize() {

	_, callbackCtx := s.authorizeCallback("valid_code")
	_, err := s.loginService.AuthCodeCallback(callbackCtx)
	require.Nil(s.T(), err)

	dummyIDPOauthServiceRef := s.getDummyOauthIDPService(true)

	keycloakToken, err := s.loginService.Exchange(callbackCtx, callbackCtx.Code, dummyIDPOauthServiceRef)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), keycloakToken)
}

func (s *serviceBlackBoxTestSuite) TestInvalidOAuthAuthorizationCodeForAuthorize() {

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

func (s *serviceBlackBoxTestSuite) TestInvalidOAuthStateForAuthorize() {

	rw, callbackCtx := s.authorizeCallback("invalid_state")
	_, err := s.loginService.AuthCodeCallback(callbackCtx)
	require.NotNil(s.T(), err)
	jsonapi.JSONErrorResponse(callbackCtx, err)
	assert.Equal(s.T(), 401, rw.Code)
}

func (s *serviceBlackBoxTestSuite) TestCreateOrUpdateIdentityAndUserOK() {
	// given
	g := s.NewTestGraph(s.T())
	config := s.Configuration
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
	identityProvider.ProfileFunc = func(ctx context.Context, tk oauth2.Token) (*oauth.UserProfile, error) {
		return &oauth.UserProfile{
			Username: user.Identity().Username,
		}, nil
	}
	// when
	resultURL, userToken, err := s.loginService.CreateOrUpdateIdentityAndUser(
		testtoken.ContextWithRequest(context.Background()),
		&url.URL{Path: redirectURL},
		oauth2Token,
		&goa.RequestData{
			Request: &http.Request{Host: "test.auth"},
		},
		identityProvider,
		config)
	// then
	require.NoError(s.T(), err)
	assert.NotNil(s.T(), resultURL)
	require.NotNil(s.T(), userToken)
	resultAccessTokenClaims, err := testtoken.TokenManager.ParseToken(context.Background(), userToken.AccessToken)
	require.NoError(s.T(), err)
	assert.NotEmpty(s.T(), resultAccessTokenClaims.SessionState)
	s.T().Logf("token claim `session_state`: %v", resultAccessTokenClaims.SessionState)

}

func (s *serviceBlackBoxTestSuite) authorizeCallback(testType string) (*httptest.ResponseRecorder, *app.CallbackAuthorizeContext) {
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

	dummyOauth := s.getDummyOauthIDPService(false)
	redirectTo, err := s.loginService.AuthCodeURL(authorizeCtx, &authorizeCtx.RedirectURI, authorizeCtx.APIClient, &authorizeCtx.State, authorizeCtx.ResponseMode, authorizeCtx.RequestData, dummyOauth, s.Configuration)
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
