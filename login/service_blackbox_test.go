package login_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	config "github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	. "github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/resource"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/fabric8-services/fabric8-auth/token"

	"github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
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
	loginService  KeycloakOAuthService
	oauth         *oauth2.Config
	dummyOauth    *dummyOauth2Config
	configuration *config.ConfigurationData
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
	s.configuration, err = config.GetConfigurationData()
	if err != nil {
		panic(fmt.Errorf("Failed to setup the configuration: %s", err.Error()))
	}

	req := &goa.RequestData{
		Request: &http.Request{Host: "api.service.domain.org"},
	}
	authEndpoint, err := s.configuration.GetKeycloakEndpointAuth(req)
	if err != nil {
		panic(err)
	}
	tokenEndpoint, err := s.configuration.GetKeycloakEndpointToken(req)
	if err != nil {
		panic(err)
	}
	s.oauth = &oauth2.Config{
		ClientID:     s.configuration.GetKeycloakClientID(),
		ClientSecret: s.configuration.GetKeycloakSecret(),
		Scopes:       []string{"user:email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  authEndpoint,
			TokenURL: tokenEndpoint,
		},
	}
	claims := make(map[string]interface{})
	accessToken, err := testtoken.GenerateTokenWithClaims(claims)
	if err != nil {
		panic(err)
	}
	s.dummyOauth = &dummyOauth2Config{
		Config: oauth2.Config{
			ClientID:     s.configuration.GetKeycloakClientID(),
			ClientSecret: s.configuration.GetKeycloakSecret(),
			Scopes:       []string{"user:email"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  authEndpoint,
				TokenURL: tokenEndpoint,
			},
		},
		accessToken: accessToken,
	}

	userRepository := account.NewUserRepository(s.DB)
	identityRepository := account.NewIdentityRepository(s.DB)
	app := gormapplication.NewGormDB(s.DB)
	s.loginService = NewKeycloakOAuthProvider(identityRepository, userRepository, testtoken.TokenManager, app)
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

	err = s.loginService.Perform(authorizeCtx, s.oauth, s.configuration)

	assert.Equal(s.T(), 307, rw.Code)
	assert.Contains(s.T(), rw.Header().Get("Location"), s.oauth.Endpoint.AuthURL)
	assert.NotEqual(s.T(), rw.Header().Get("Location"), "")
}

func (s *serviceBlackBoxTest) TestApprovedUserCreatedAndUpdated() {
	claims := make(map[string]interface{})
	token, err := testtoken.GenerateTokenWithClaims(claims)
	require.Nil(s.T(), err)

	identity, ok, err := s.loginService.CreateOrUpdateIdentity(context.Background(), token, s.configuration)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), identity)
	assert.True(s.T(), ok)
	s.checkIfTokenMatchesIdentity(token, *identity)
	assert.Equal(s.T(), s.configuration.GetOpenShiftClientApiUrl(), identity.User.Cluster)

	updatedClaims := make(map[string]interface{})
	updatedClaims["company"] = "Updated company"
	updatedClaims["preferred_username"] = uuid.NewV4().String()
	updatedClaims["name"] = "Updated Name"
	updatedClaims["given_name"] = "Updated"
	updatedClaims["family_name"] = "Name"

	token, err = testtoken.UpdateToken(token, updatedClaims)
	require.Nil(s.T(), err)

	identity, ok, err = s.loginService.CreateOrUpdateIdentity(context.Background(), token, s.configuration)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), identity)
	assert.False(s.T(), ok)
	s.checkIfTokenMatchesIdentity(token, *identity)
}

func (s *serviceBlackBoxTest) TestUnapprovedUserUnauthorized() {
	claims := make(map[string]interface{})
	claims["approved"] = false
	token, err := testtoken.GenerateTokenWithClaims(claims)
	require.Nil(s.T(), err)

	_, _, err = s.loginService.CreateOrUpdateIdentity(context.Background(), token, s.configuration)
	require.NotNil(s.T(), err)
	require.IsType(s.T(), errors.NewUnauthorizedError(""), err)
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

	err = s.loginService.Perform(authorizeCtx, s.oauth, s.configuration)

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

	err = s.loginService.Perform(authorizeCtx, s.oauth, s.configuration)
	assert.Equal(s.T(), 400, rw.Code)
}

func (s *serviceBlackBoxTest) TestKeycloakAuthorizationWithNoValidRefererFails() {

	// since we no longer pass the valid redirect urls as a parameter,
	existingValidRedirects := os.Getenv("AUTH_REDIRECT_VALID")
	defer func() {
		os.Setenv("AUTH_REDIRECT_VALID", existingValidRedirects)
		config, err := config.GetConfigurationData()
		assert.Nil(s.T(), err)
		s.configuration = config
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

	err = s.loginService.Perform(authorizeCtx, s.oauth, s.configuration)
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

	err = s.loginService.Perform(authorizeCtx, s.oauth, s.configuration)
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

	err = s.loginService.Perform(authorizeCtx, s.oauth, s.configuration)
	assert.Equal(s.T(), 307, rw.Code)
	assert.Contains(s.T(), rw.Header().Get("Location"), s.oauth.Endpoint.AuthURL)
	assert.NotEqual(s.T(), rw.Header().Get("Location"), "")
}

func (s *serviceBlackBoxTest) TestKeycloakLinkRedirect() {
	keycloakLinkRedirect(s, "", "")
	keycloakLinkRedirect(s, "", "https://some.redirect.io")
	keycloakLinkRedirect(s, "github", "")
	keycloakLinkRedirect(s, "github", "https://some.redirect.io")
	keycloakLinkRedirect(s, "openshift-v3", "")
	keycloakLinkRedirect(s, "openshift-v3", "https://some.redirect.io")
}

func keycloakLinkRedirect(s *serviceBlackBoxTest, provider string, redirect string) {
	rw := httptest.NewRecorder()
	p := "/api/link"

	parameters := url.Values{}
	if redirect != "" {
		parameters.Add("redirect", redirect)
	}
	if provider != "" {
		parameters.Add("provider", provider)
	}

	req, err := http.NewRequest("GET", p, nil)
	require.Nil(s.T(), err)

	referrerUrl := "https://example.org/path"
	req.Header.Add("referer", referrerUrl)

	ss := uuid.NewV4().String()
	claims := jwt.MapClaims{}
	claims["session_state"] = &ss
	token := &jwt.Token{Claims: claims}
	ctx := goajwt.WithJWT(context.Background(), token)
	goaCtx := goa.NewContext(goa.WithAction(ctx, "LinkTest"), rw, req, parameters)

	linkCtx, err := app.NewLinkLinkContext(goaCtx, req, goa.New("LinkService"))
	require.Nil(s.T(), err)

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}
	brokerEndpoint, err := s.configuration.GetKeycloakEndpointBroker(r)
	require.Nil(s.T(), err)
	clientID := s.configuration.GetKeycloakClientID()

	err = s.loginService.Link(linkCtx, brokerEndpoint, clientID, s.configuration.GetValidRedirectURLs())
	require.Nil(s.T(), err)

	assert.Equal(s.T(), 307, rw.Code)
	redirectLocation := rw.Header().Get("Location")
	if provider == "" {
		provider = "github"
		assert.Contains(s.T(), redirectLocation, "next%3Dopenshift-v3")
	} else {
		assert.NotContains(s.T(), redirectLocation, "next%3D")
	}
	location := brokerEndpoint + "/" + provider + "/link?"
	assert.Contains(s.T(), redirectLocation, location)
}

func keycloakLinkCallbackRedirect(s *serviceBlackBoxTest, next string) {
	rw := httptest.NewRecorder()
	p := "/api/link/callback"

	parameters := url.Values{}
	parameters.Add("state", uuid.NewV4().String())
	parameters.Add("sessionState", uuid.NewV4().String())
	if next != "" {
		parameters.Add("next", next)
	}
	req, err := http.NewRequest("GET", p, nil)
	require.Nil(s.T(), err)

	referrerUrl := "https://sso.example.org/path"
	req.Header.Add("referer", referrerUrl)

	goaCtx := goa.NewContext(goa.WithAction(context.Background(), "LinkcallbackTest"), rw, req, parameters)

	linkCtx, err := app.NewCallbackLinkContext(goaCtx, req, goa.New("LinkService"))
	require.Nil(s.T(), err)

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}
	brokerEndpoint, err := s.configuration.GetKeycloakEndpointBroker(r)
	require.Nil(s.T(), err)
	clientID := s.configuration.GetKeycloakClientID()

	err = s.loginService.LinkCallback(linkCtx, brokerEndpoint, clientID)
	if next != "" {
		require.Nil(s.T(), err)
		assert.Equal(s.T(), 307, rw.Code)
		redirectLocation := rw.Header().Get("Location")
		assert.NotContains(s.T(), redirectLocation, "next%3D")
		location := brokerEndpoint + "/openshift-v3/link?"
		assert.Contains(s.T(), redirectLocation, location)
	} else {
		require.NotNil(s.T(), err)
	}
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
	err = s.loginService.Perform(authorizeCtx, s.oauth, s.configuration)
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

	err = s.loginService.Perform(authorizeCtx, s.oauth, s.configuration)

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

	err = s.loginService.Perform(authorizeCtx, s.oauth, s.configuration)

	locationString = rw.HeaderMap["Location"][0]
	locationUrl, err = url.Parse(locationString)
	require.Nil(s.T(), err)

	allQueryParameters = locationUrl.Query()
	assert.Equal(s.T(), 307, rw.Code) // redirect to ALM page where login was clicked.
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

	err = s.loginService.Perform(authorizeCtx, dummyOauth, s.configuration)
	require.NotNil(s.T(), err)
	assert.Equal(s.T(), 401, rw.Code)

	assert.Equal(s.T(), 0, len(rw.HeaderMap["Location"]))
}

func (s *serviceBlackBoxTest) TestAPIClientForApprovedUsersReturnOK() {
	extra := make(map[string]string)
	extra["api_client"] = "vscode"
	rw, authorizeCtx := s.loginCallback(extra)

	claims := make(map[string]interface{})
	accessToken, err := testtoken.GenerateTokenWithClaims(claims)
	require.Nil(s.T(), err)

	dummyOauth := &dummyOauth2Config{
		Config:      oauth2.Config{},
		accessToken: accessToken,
	}

	s.checkLoginCallback(dummyOauth, rw, authorizeCtx, "api_token")
}

func (s *serviceBlackBoxTest) TestAPIClientForUnapprovedUsersReturnOK() {
	extra := make(map[string]string)
	extra["api_client"] = "vscode"
	rw, authorizeCtx := s.loginCallback(extra)

	claims := make(map[string]interface{})
	claims["approved"] = nil
	accessToken, err := testtoken.GenerateTokenWithClaims(claims)
	require.Nil(s.T(), err)

	dummyOauth := &dummyOauth2Config{
		Config:      oauth2.Config{},
		accessToken: accessToken,
	}

	s.checkLoginCallback(dummyOauth, rw, authorizeCtx, "api_token")
}

func (s *serviceBlackBoxTest) loginCallback(extraParams map[string]string) (*httptest.ResponseRecorder, *app.LoginLoginContext) {
	// Setup request context
	rw := httptest.NewRecorder()
	u := &url.URL{
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

	err = s.loginService.Perform(authorizeCtx, s.dummyOauth, s.configuration)
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

	err := s.loginService.Perform(authorizeCtx, dummyOauth, s.configuration)
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
	require.Nil(s.T(), err)
	assert.Equal(s.T(), dummyOauth.accessToken, *tokenSet.AccessToken)
	assert.Equal(s.T(), "someRefreshToken", *tokenSet.RefreshToken)

	assert.NotContains(s.T(), locationString, "https://keycloak-url.example.org/path-of-login")
	assert.Contains(s.T(), locationString, "https://openshift.io/somepath")
}

type dummyOauth2Config struct {
	oauth2.Config
	accessToken string
}

func (c *dummyOauth2Config) Exchange(ctx netcontext.Context, code string) (*oauth2.Token, error) {
	var thirtyDays int64
	thirtyDays = 60 * 60 * 24 * 30
	token := &oauth2.Token{
		TokenType:    "Bearer",
		AccessToken:  c.accessToken,
		RefreshToken: "someRefreshToken",
		Expiry:       time.Unix(time.Now().Unix()+thirtyDays, 0),
	}
	extra := make(map[string]interface{})
	extra["expires_in"] = time.Now().Unix() + thirtyDays
	extra["refresh_expires_in"] = time.Now().Unix() + thirtyDays
	token = token.WithExtra(extra)
	return token, nil
}
