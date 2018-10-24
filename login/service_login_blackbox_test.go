package login_test

import (
	"context"
	"encoding/json"
	"fmt"
	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/app"
	//"github.com/fabric8-services/fabric8-auth/configuration"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/goadesign/goa"
	"github.com/stretchr/testify/assert"
	"strings"

	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/resource"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	"github.com/goadesign/goa/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestServiceLoginBlackboxTest(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &serviceLoginBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})

}

type serviceLoginBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	//configuration      *configuration.ConfigurationData
	IDPServer          *httptest.Server
	WITServer          *httptest.Server
	witIdentityIDCache []string
	state              string
	approved           bool
	identity           *account.Identity
	alreadyLoggedIn    bool
}

func (s *serviceLoginBlackBoxTest) SetupSuite() {
	s.IDPServer = s.createMockHTTPServer(s.serveOauthServer)
	s.state = uuid.NewV4().String()
	idpServerURL := "http://" + s.IDPServer.Listener.Addr().String() + "/api/"

	os.Setenv("AUTH_OAUTH_ENDPOINT_USERINFO", idpServerURL+"profile")
	os.Setenv("AUTH_OAUTH_ENDPOINT_AUTH", idpServerURL+"code")
	os.Setenv("AUTH_OAUTH_ENDPOINT_TOKEN", idpServerURL+"token")

	s.WITServer = s.createMockHTTPServer(s.serveWITServer)
	witServerURL := "http://" + s.WITServer.Listener.Addr().String()
	os.Setenv("AUTH_WIT_URL", witServerURL)

	s.DBTestSuite.SetupSuite()
}

func (s *serviceLoginBlackBoxTest) TearDownSuite() {
	s.IDPServer.CloseClientConnections()
	s.IDPServer.Close()
	s.WITServer.CloseClientConnections()
	s.WITServer.Close()
	os.Unsetenv("AUTH_ENDPOINT_USERINFO")
	os.Unsetenv("AUTH_OAUTH_ENDPOINT_AUTH")
	os.Unsetenv("AUTH_OAUTH_ENDPOINT_TOKEN")
	os.Unsetenv("AUTH_WIT_URL")
}

func (s *serviceLoginBlackBoxTest) TestLoginEndToEnd() {
	s.approved = true
	s.alreadyLoggedIn = false
	s.runLoginEndToEnd()

	// login successful, try doing multiple logins.
	for i := 0; i < 10; i++ {
		s.alreadyLoggedIn = true
		s.runLoginEndToEnd()
	}
}

func (s *serviceLoginBlackBoxTest) TestLoginEndToEndNotApproved() {
	s.approved = false
	s.alreadyLoggedIn = false
	s.runLoginEndToEnd()

	// login failed, try doing multiple logins and see the same result.
	for i := 0; i < 10; i++ {
		s.alreadyLoggedIn = false
		s.runLoginEndToEnd()
	}
}

func (s *serviceLoginBlackBoxTest) runLoginEndToEnd() {
	idpServerURL := "http://" + s.IDPServer.Listener.Addr().String() + "/api/"
	prms := url.Values{}

	authorizeCtx, rw := s.createNewLoginContext("/api/login", prms)
	service := s.createNewLoginService()

	// ############ STEP 1 Call /api/login without state or code
	// ############
	err := service.Login(authorizeCtx, login.NewIdentityProvider(s.Configuration), s.Configuration)
	require.Nil(s.T(), err)

	// Ensure you get a redirect with a 'state'
	require.Equal(s.T(), 307, rw.Code)
	redirectURL := rw.Header().Get("location")
	require.Contains(s.T(), redirectURL, idpServerURL)

	// ############ STEP 2: Simulate what happens in the front-end
	// ############ redirect to the oauth server login page.

	reqToOauthServer, err := http.NewRequest("GET", redirectURL, nil)
	if err != nil {
		panic("invalid test " + err.Error()) // bug
	}

	// set a referrer so that our simulation can bring us back
	refererUrl := "auth.openshift.io/api/login"
	reqToOauthServer.Header.Add("referer", refererUrl)
	resp, err := http.DefaultClient.Do(reqToOauthServer)

	require.NoError(s.T(), err)
	require.Contains(s.T(), resp.Header.Get("Location"), refererUrl)

	// ########### Step 3: Use the same state to
	// ########### make a call to /api/login?code=XXXX&state=XXXXYYY

	successRedirectURL, err := url.Parse(resp.Header.Get("Location"))
	require.Nil(s.T(), err)

	returnedState := successRedirectURL.Query()["state"][0]
	returnedCode := successRedirectURL.Query()["code"][0]

	// set the state so that our oauth server can callback to /api/login with this state
	s.state = returnedState

	// Call /api/login?code=X&state=Y
	prms = url.Values{"state": []string{returnedState}, "code": []string{returnedCode}}
	rw = httptest.NewRecorder()
	authorizeCtx, rw = s.createNewLoginContext("/api/login", prms)
	err = service.Login(authorizeCtx, login.NewIdentityProvider(s.Configuration), s.Configuration)

	//  ############ STEP 4: Token generated and received as a param in the redirect
	//  ############ Validate that there was redirect recieved.
	if s.approved {
		require.Nil(s.T(), err)
		require.NotEmpty(s.T(), rw.Header().Get("Location"))
		require.Equal(s.T(), 307, rw.Code)

		// From the redirect pick up the token_json param
		successURL, err := url.Parse((rw.Header().Get("Location")))
		require.Nil(s.T(), err)
		allQueryParameters := successURL.Query()
		require.NotNil(s.T(), allQueryParameters)
		tokenJson := allQueryParameters["token_json"]
		require.NotNil(s.T(), tokenJson)
		require.True(s.T(), len(tokenJson) > 0)

		// Validate the token returned contains the identity details for which the oauth server had
		// returned the token.
		returnedToken, err := token.ReadTokenSetFromJson(context.Background(), tokenJson[0])
		require.NoError(s.T(), err)

		updatedIdentity := s.Graph.LoadUser(s.identity.ID).Identity()
		require.NotNil(s.T(), updatedIdentity)
		s.identity = updatedIdentity
		checkIfTokenMatchesIdentity(s.T(), *returnedToken.AccessToken, *updatedIdentity)
		require.True(s.T(), s.identity.RegistrationCompleted)
	} else {
		require.Equal(s.T(), 401, rw.Code)
	}

}

// ############################
// Tests for oauth2
// ############################

func (s *serviceLoginBlackBoxTest) TestOauth2LoginEndToEnd() {
	s.approved = true
	s.alreadyLoggedIn = false
	modeFragment := "fragment"
	s.runOauth2LoginEndToEnd("https://che.openshift.io/dashboard/#/factories", modeFragment)
	s.runOauth2LoginEndToEnd("https://randomurl/with/#fragment", modeFragment)
	s.runOauth2LoginEndToEnd("https://randomurl/with", modeFragment)
	s.runOauth2LoginEndToEnd("https://randomurl/with/", modeFragment)
	s.runOauth2LoginEndToEnd("https://randomurl/with/?test", modeFragment)

	modeQuery := "query"
	s.runOauth2LoginEndToEnd("https://randomurl/with/#fragment", modeQuery)

}

func (s *serviceLoginBlackBoxTest) TestOauth2LoginEndToEndNotApproved() {
	s.approved = false
	s.alreadyLoggedIn = false
	modeFragment := "fragment"
	s.runOauth2LoginEndToEnd("https://che.openshift.io/dashboard/#/factories", modeFragment)
}

func (s *serviceLoginBlackBoxTest) runOauth2LoginEndToEnd(redirectURL string, responseMode string) {

	clientID := s.Configuration.GetPublicOauthClientID()
	state := uuid.NewV4().String()
	resonseType := "code"

	prms := url.Values{"response_mode": []string{responseMode}, "response_type": []string{resonseType}, "client_id": []string{clientID}, "state": []string{state}, "redirect_uri": []string{redirectURL}}

	authorizeCtx, _ := s.createNewAuthCodeURLContext("/api/authorize", prms)
	service := s.createNewLoginService()

	// ############ STEP 1 Call /api/authorize without state or code
	// ############
	oauthConfig := login.NewIdentityProvider(s.Configuration)
	oauthCodeRedirectURL := "http://auth.openshift.io/authorize/callback"
	oauthConfig.RedirectURL = oauthCodeRedirectURL
	redirectedTo, err := service.AuthCodeURL(authorizeCtx, &redirectURL, nil, &state, &responseMode, authorizeCtx.RequestData, oauthConfig, s.Configuration)
	require.Nil(s.T(), err)

	// Ensure you get a redirect with a 'state'
	require.Contains(s.T(), *redirectedTo, s.Configuration.GetOAuthEndpointAuth())

	redirectedToURLRef, err := url.Parse(*redirectedTo)
	require.NoError(s.T(), err)

	require.Equal(s.T(), state, redirectedToURLRef.Query()["state"][0])
	require.Equal(s.T(), resonseType, redirectedToURLRef.Query()["response_type"][0])
	require.Equal(s.T(), s.Configuration.GetKeycloakClientID(), redirectedToURLRef.Query()["client_id"][0])

	// This is what the OAuth server calls after the user puts in her credentials.
	require.Equal(s.T(), oauthCodeRedirectURL, redirectedToURLRef.Query()["redirect_uri"][0])

	// ############ STEP 2: The oauthserver calls the callback url
	// ############

	reqToOauthServer, err := http.NewRequest("GET", *redirectedTo, nil)
	reqToOauthServer.Header.Add("referrer", "http://notimportant")
	reqToOauthServer.Header.Add("Accept-Encoding", "identity")

	if err != nil {
		panic("invalid test " + err.Error()) // bug
	}

	resp, err := http.DefaultClient.Do(reqToOauthServer)

	require.NoError(s.T(), err)
	require.Contains(s.T(), resp.Header.Get("Location"), oauthCodeRedirectURL)

	redirectedToURLRef, err = url.Parse(resp.Header.Get("Location"))
	require.NoError(s.T(), err)

	returnedCode := redirectedToURLRef.Query()["code"][0]
	returnedState := redirectedToURLRef.Query()["state"][0]
	require.NotEmpty(s.T(), returnedCode)
	require.Equal(s.T(), state, returnedState)

	// ########### Step 3 : Let's call /api/authorize/callback?code=XXXX&state=YYYYY
	// ########### as if it was called by the oauth server.

	prms = url.Values{"state": []string{returnedState}, "code": []string{returnedCode}}
	authorizeCallbackCtx, _ := s.createNewAuthCallbackContext("/api/authorize/callback", prms)
	redirectedTo, err = service.AuthCodeCallback(authorizeCallbackCtx)
	require.NotNil(s.T(), redirectedTo)
	require.NoError(s.T(), err)

	redirectedToURLRef, err = url.Parse(*redirectedTo)
	require.NoError(s.T(), err)

	// All existing params should be carried over as is
	originalRedirectURLRef, err := url.Parse(redirectURL)
	require.NoError(s.T(), err)

	for i := range originalRedirectURLRef.Query() {
		require.Contains(s.T(), redirectedToURLRef.Query(), i)
	}

	if responseMode == "fragment" {

		require.Contains(s.T(), *redirectedTo, redirectURL)
		require.Contains(s.T(), redirectedToURLRef.Fragment, fmt.Sprintf("state=%s", returnedState))
		require.Contains(s.T(), redirectedToURLRef.Fragment, fmt.Sprintf("code=%s", returnedCode))

		// Ensure that existing params are NOT being carried over as fragments
		for i := range originalRedirectURLRef.Query() {
			require.NotContains(s.T(), redirectedToURLRef.Fragment, fmt.Sprintf("%s=", i))
		}

		// ensures that the initial fragment is in the right position
		require.Contains(s.T(), *redirectedTo, redirectURL)

	} else {

		require.Equal(s.T(), returnedCode, redirectedToURLRef.Query()["code"][0])
		require.Equal(s.T(), returnedState, redirectedToURLRef.Query()["state"][0])

	}

	//  ############ STEP 4: Ask for a token ( the way it would be asked using POST /api/token )
	//  ############ Validate that there was redirect recieved.

	returnedToken, err := service.Exchange(context.Background(), returnedCode, oauthConfig)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), returnedToken)
	require.NotEmpty(s.T(), returnedToken.AccessToken)

	tokenContext, _ := s.createNewTokenContext("/api/token", prms)
	_, authToken, err := service.CreateOrUpdateIdentityAndUser(tokenContext, redirectedToURLRef, returnedToken, tokenContext.RequestData, oauthConfig, s.Configuration)
	if s.approved {
		require.NoError(s.T(), err)
		require.NotNil(s.T(), authToken)

		checkIfTokenMatchesIdentity(s.T(), authToken.AccessToken, *s.identity)
	} else {
		require.Error(s.T(), err)
		require.Nil(s.T(), authToken)
	}
}

func (s *serviceLoginBlackBoxTest) createNewLoginContext(path string, prms url.Values) (*app.LoginLoginContext, *httptest.ResponseRecorder) {
	rw := httptest.NewRecorder()
	u := &url.URL{
		Path: fmt.Sprintf(path),
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		panic("invalid test " + err.Error()) // bug
	}

	refererUrl := "https://alm-url.example.org/path/oauth2"
	req.Header.Add("referer", refererUrl)

	ctx := testtoken.ContextWithTokenManager()
	goaCtx := goa.NewContext(goa.WithAction(ctx, "LoginTest"), rw, req, prms)
	loginCtx, err := app.NewLoginLoginContext(goaCtx, req, goa.New("LoginService"))
	require.NoError(s.T(), err)
	return loginCtx, rw
}

func (s *serviceLoginBlackBoxTest) createNewTokenContext(path string, prms url.Values) (*app.CallbackAuthorizeContext, *httptest.ResponseRecorder) {
	rw := httptest.NewRecorder()
	u := &url.URL{
		Path: fmt.Sprintf(path),
	}
	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		panic("invalid test " + err.Error()) // bug
	}

	refererUrl := "https://alm-url.example.org/path/oauth2/callback"
	req.Header.Add("referer", refererUrl)

	ctx := testtoken.ContextWithTokenManager()
	goaCtx := goa.NewContext(goa.WithAction(ctx, "TokenContext"), rw, req, prms)
	loginCtx, err := app.NewCallbackAuthorizeContext(goaCtx, req, goa.New("TokenContextService"))
	require.NoError(s.T(), err)
	return loginCtx, rw
}

func (s *serviceLoginBlackBoxTest) createNewAuthCallbackContext(path string, prms url.Values) (*app.CallbackAuthorizeContext, *httptest.ResponseRecorder) {
	rw := httptest.NewRecorder()
	u := &url.URL{
		Path: fmt.Sprintf(path),
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		panic("invalid test " + err.Error()) // bug
	}

	refererUrl := "https://alm-url.example.org/path/oauth2/callback"
	req.Header.Add("referer", refererUrl)

	ctx := testtoken.ContextWithTokenManager()
	goaCtx := goa.NewContext(goa.WithAction(ctx, "AuthCallbackTest"), rw, req, prms)
	loginCtx, err := app.NewCallbackAuthorizeContext(goaCtx, req, goa.New("AuthCallbackService"))
	require.NoError(s.T(), err)
	return loginCtx, rw
}

func (s *serviceLoginBlackBoxTest) createNewAuthCodeURLContext(path string, prms url.Values) (*app.AuthorizeAuthorizeContext, *httptest.ResponseRecorder) {
	rw := httptest.NewRecorder()
	u := &url.URL{
		Path: fmt.Sprintf(path),
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		panic("invalid test " + err.Error()) // bug
	}

	refererUrl := "https://alm-url.example.org/path"
	req.Header.Add("referer", refererUrl)

	ctx := testtoken.ContextWithTokenManager()
	goaCtx := goa.NewContext(goa.WithAction(ctx, "AuthTest"), rw, req, prms)
	loginCtx, err := app.NewAuthorizeAuthorizeContext(goaCtx, req, goa.New("AuthService"))
	require.NoError(s.T(), err)
	return loginCtx, rw
}

func (s *serviceLoginBlackBoxTest) createNewLoginService() *login.KeycloakOAuthProvider {
	return login.NewKeycloakOAuthProvider(
		s.Application.Identities(),
		s.Application.Users(),
		testtoken.TokenManager,
		s.Application,
		nil,
		&testsupport.DummyOSORegistrationApp{},
	)
}

func checkIfTokenMatchesIdentity(t *testing.T, tokenString string, identity account.Identity) {
	claims, err := testtoken.TokenManager.ParseToken(context.Background(), tokenString)
	require.Nil(t, err)
	assert.Equal(t, identity.Username, claims.Username)
	assert.Equal(t, identity.User.Email, claims.Email)
	assert.Equal(t, identity.ID.String(), claims.Subject)

	// On first login, this info is pulled from the userinfo and populated.
	// On Subsequent logins, irrespective of what RHD userinfo returns,
	// the identity data in the DB remains the same.
	assert.Equal(t, "GIVEN_NAME_OVERRIDE FAMILY_NAME_OVERRIDE", claims.Name)
	assert.Equal(t, "FAMILY_NAME_OVERRIDE", claims.FamilyName)
	assert.Equal(t, "GIVEN_NAME_OVERRIDE", claims.GivenName)
	assert.Equal(t, "COMPANY_OVERRIDE", claims.Company)
}

// ############################
// Run a mocked Oauth IDP server
// #############################

func (s *serviceLoginBlackBoxTest) createOauthServer(handle func(http.ResponseWriter, *http.Request)) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handle)
	return httptest.NewServer(mux)
}

func (s *serviceLoginBlackBoxTest) serveOauthServer(rw http.ResponseWriter, req *http.Request) {

	if req.URL.Path == "/api/code" {

		if !s.alreadyLoggedIn {
			// new user only if user is logging in for the first time.
			// This bit comes handy to determine outcome of multiple logins by the same user
			s.identity = s.Graph.CreateUser(s.Graph.ID(uuid.NewV4().String())).Identity()
			require.NotEmpty(s.T(), s.identity.Username)
		}

		//require.NotEmpty(s.T(), req.Referer())
		urlRef, err := url.Parse(req.Referer())
		require.NoError(s.T(), err)

		// redirect_uri takes higher precedencefalse
		if len(req.URL.Query().Get("redirect_uri")) > 0 {
			urlRef, err = url.Parse(req.URL.Query().Get("redirect_uri"))
			require.NoError(s.T(), err)
		}

		params := urlRef.Query()
		params.Add("code", uuid.NewV4().String())
		params.Add("state", req.URL.Query().Get("state"))
		urlRef.RawQuery = params.Encode()
		rw.Header().Set("Location", urlRef.String())

	} else if req.URL.Path == "/api/token" {

		claims := make(map[string]interface{})

		if s.approved {
			// if it's an approved scenario, then issue a token which has an existing username
			claims["preferred_username"] = s.identity.Username
			claims["name"] = s.identity.User.FullName
		}

		accessToken, err := testtoken.GenerateAccessTokenWithClaims(claims)
		require.NoError(s.T(), err)

		refreshToken, err := testtoken.GenerateRefreshTokenWithClaims(claims)
		require.NoError(s.T(), err)

		expires_in := time.Now().Unix() + 60*60*24*30
		tokenResponse := fmt.Sprintf("{\"access_token\":\"%s\",\"refresh_token\":\"%s\",\"expires_in\":\"%s\",\"token_type\":\"%s\"}", accessToken, refreshToken, strconv.FormatInt(expires_in, 10), "bearer")
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(tokenResponse))

	} else if req.URL.Path == "/api/profile" {
		require.NotEqual(s.T(), "Bearer", req.Header.Get("authorization"))
		userResponse := login.IdentityProviderResponse{
			Username:   s.identity.Username,
			Subject:    s.identity.ID.String(),
			Company:    uuid.NewV4().String(),
			Email:      s.identity.User.Email,
			FamilyName: uuid.NewV4().String(),
			GivenName:  uuid.NewV4().String(),
		}

		if !s.approved {
			userResponse.Username = uuid.NewV4().String()
		}

		// Return a fixed value only on first login.
		// On subsequent logins, the values would be populated by random data.
		// In spite of that, the token would always have claims populated from DB.

		// This randomization is to test that even if RHD userinfo returns different profile data
		// on every login, we wouldn't be updating that in the db - except on the first login.
		if !s.alreadyLoggedIn {
			userResponse.FamilyName = "FAMILY_NAME_OVERRIDE"
			userResponse.GivenName = "GIVEN_NAME_OVERRIDE"
			userResponse.Company = "COMPANY_OVERRIDE"
		}
		inBytes, _ := json.Marshal(userResponse)
		rw.Header().Set("Content-Type", "application/json")
		rw.Write(inBytes)
	}
}

func (s *serviceLoginBlackBoxTest) createMockHTTPServer(handle func(http.ResponseWriter, *http.Request)) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handle)
	return httptest.NewServer(mux)
}
func (s *serviceLoginBlackBoxTest) serveWITServer(rw http.ResponseWriter, req *http.Request) {
	// keep an eye on calls going to POST /api/users/:identityID
	if strings.Contains(req.URL.Path, "users") && req.Method == "POST" {
		s.witIdentityIDCache = append(s.witIdentityIDCache, strings.Split(req.URL.Path, "/users/")[1])
	}
}
