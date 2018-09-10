package login_test

import (
	"context"
	"encoding/json"
	"fmt"
	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/configuration"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/goadesign/goa"
	"github.com/stretchr/testify/assert"

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
	configuration *configuration.ConfigurationData
	IDPServer     *httptest.Server
	state         string
	approved      bool
	identity      *account.Identity
}

func (s *serviceLoginBlackBoxTest) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	s.IDPServer = s.createOauthServer(s.serveOauthServer)
	s.state = uuid.NewV4().String()
	idpServerURL := "http://" + s.IDPServer.Listener.Addr().String() + "/api/"

	os.Setenv("AUTH_ENDPOINT_USERINFO", idpServerURL+"profile")
	os.Setenv("AUTH_OAUTH_ENDPOINT_AUTH", idpServerURL+"code")
	os.Setenv("AUTH_OAUTH_ENDPOINT_TOKEN", idpServerURL+"token")
	config, err := configuration.GetConfigurationData()
	require.Nil(s.T(), err)
	s.configuration = config

}

func (s *serviceLoginBlackBoxTest) TearDownSuite() {
	s.IDPServer.CloseClientConnections()
	s.IDPServer.Close()
	os.Unsetenv("AUTH_ENDPOINT_USERINFO")
	os.Unsetenv("AUTH_OAUTH_ENDPOINT_AUTH")
	os.Unsetenv("AUTH_OAUTH_ENDPOINT_TOKEN")
}

func (s *serviceLoginBlackBoxTest) TestLoginEndToEnd() {
	s.approved = true
	s.runLoginEndToEnd()
}

func (s *serviceLoginBlackBoxTest) TestLoginEndToEndNotApproved() {
	s.approved = false
	s.runLoginEndToEnd()
}

func (s *serviceLoginBlackBoxTest) runLoginEndToEnd() {
	idpServerURL := "http://" + s.IDPServer.Listener.Addr().String() + "/api/"
	prms := url.Values{}
	s.approved = true

	authorizeCtx, rw := s.createNewLoginContext("/api/login", prms)
	service := s.createNewLoginService()

	// ############ STEP 1 Call /api/login without state or code
	// ############
	err := service.Login(authorizeCtx, login.NewLoginIdentityProvider(s.configuration), s.configuration)
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
	err = service.Login(authorizeCtx, login.NewLoginIdentityProvider(s.configuration), s.configuration)

	//  ############ STEP 4: Token generated and recieved as a param in the redirect
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

		checkIfTokenMatchesIdentity(s.T(), *returnedToken.AccessToken, *s.identity)
	} else {
		require.Equal(s.T(), 401, rw.Code)
	}

}

// ############################
// Tests for oauth2
// ############################

func (s *serviceLoginBlackBoxTest) TestOauth2LoginEndToEnd() {
	s.approved = true
	s.runOauth2LoginEndToEnd()

}

func (s *serviceLoginBlackBoxTest) TestOauth2LoginEndToEndNotApproved() {
	s.approved = false
	s.runOauth2LoginEndToEnd()
}

func (s *serviceLoginBlackBoxTest) runOauth2LoginEndToEnd() {

	redirectURL := "https://auth.openshift.io/api/status"
	apiClient := s.Configuration.GetPublicOauthClientID()
	state := uuid.NewV4().String()
	resonseType := "code"

	prms := url.Values{"response_type": []string{resonseType}, "client_id": []string{apiClient}, "state": []string{state}, "redirect_uri": []string{redirectURL}}

	authorizeCtx, _ := s.createNewAuthCodeURLContext("/api/authorize", prms)
	service := s.createNewLoginService()

	// ############ STEP 1 Call /api/authorize without state or code
	// ############
	oauthConfig := login.NewLoginIdentityProvider(s.Configuration)
	oauthCodeRedirectURL := "http://auth.openshift.io/authorize/callback"
	oauthConfig.RedirectURL = oauthCodeRedirectURL
	redirectedTo, err := service.AuthCodeURL(authorizeCtx, &redirectURL, &apiClient, &state, nil, authorizeCtx.RequestData, oauthConfig, s.Configuration)
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
	require.Equal(s.T(), redirectURL, redirectedToURLRef.Scheme+"://"+redirectedToURLRef.Host+redirectedToURLRef.Path)
	require.Equal(s.T(), s.Configuration.GetPublicOauthClientID(), redirectedToURLRef.Query()["api_client"][0])
	require.Equal(s.T(), state, redirectedToURLRef.Query()["state"][0])
	require.Equal(s.T(), returnedCode, redirectedToURLRef.Query()["code"][0])

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
		nil,
		&testsupport.DummyOSORegistrationApp{},
	)
}

func checkIfTokenMatchesIdentity(t *testing.T, tokenString string, identity account.Identity) {
	claims, err := testtoken.TokenManager.ParseToken(context.Background(), tokenString)
	require.Nil(t, err)
	assert.Equal(t, claims.Company, identity.User.Company)
	assert.Equal(t, claims.Username, identity.Username)
	assert.Equal(t, claims.Email, identity.User.Email)
	assert.Equal(t, claims.Subject, identity.ID.String())
	assert.Equal(t, claims.Name, identity.User.FullName)
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

		s.identity = s.Graph.CreateUser(s.Graph.ID(uuid.NewV4().String())).Identity()

		//require.NotEmpty(s.T(), req.Referer())
		urlRef, err := url.Parse(req.Referer())
		require.NoError(s.T(), err)

		// redirect_uri takes higher precedence
		if len(req.URL.Query().Get("redirect_uri")) > 0 {
			urlRef, err = url.Parse(req.URL.Query().Get("redirect_uri"))
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
		userResponse := login.LoginIdentityProviderResponse{
			Username: s.identity.Username,
			Subject:  s.identity.ID.String(),
			Company:  s.identity.User.Company,
			Email:    s.identity.User.Email,
		}

		if !s.approved {
			userResponse.Username = uuid.NewV4().String()
		}
		inBytes, _ := json.Marshal(userResponse)
		rw.Header().Set("Content-Type", "application/json")
		rw.Write(inBytes)
	}
}
