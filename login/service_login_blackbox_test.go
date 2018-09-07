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

	"net/url"
	"strconv"
	"time"
	//autherror "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/resource"
	//"github.com/fabric8-services/fabric8-auth/token/oauth"
	"github.com/goadesign/goa/uuid"
	//"github.com/pkg/errors"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	//"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	//"golang.org/x/oauth2"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestServiceLoginBlackboxTest(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &serviceLoginBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})

}

type serviceLoginBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	IDPServer    *httptest.Server
	config       *configuration.ConfigurationData
	state        string
	accessToken  string
	approved     bool
	refreshToken string
	identity     *account.Identity
}

func (s *serviceLoginBlackBoxTest) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	s.IDPServer = s.createOauthServer(s.serveOauthServer)
	s.state = uuid.NewV4().String()
}

func (s *serviceLoginBlackBoxTest) TearDownSuite() {
	s.IDPServer.CloseClientConnections()
	s.IDPServer.Close()
}

func (s *serviceLoginBlackBoxTest) getCustomConfig() *configuration.ConfigurationData {
	idpServerURL := "http://" + s.IDPServer.Listener.Addr().String() + "/api/"
	os.Setenv("AUTH_ENDPOINT_USERINFO", idpServerURL+"profile")
	os.Setenv("AUTH_OAUTH_ENDPOINT_AUTH", idpServerURL+"code")
	os.Setenv("AUTH_OAUTH_ENDPOINT_TOKEN", idpServerURL+"token")
	config, err := configuration.GetConfigurationData()
	require.Nil(s.T(), err)
	return config
}

func (s *serviceLoginBlackBoxTest) TestRedirectToLoginPage() {

}

func (s *serviceLoginBlackBoxTest) TestLoginEndToEnd() {
	idpServerURL := "http://" + s.IDPServer.Listener.Addr().String() + "/api/"
	prms := url.Values{}
	s.approved = true

	authorizeCtx, rw := s.createNewLoginContext("/api/login", prms)
	service := s.createNewLoginService()
	customConfig := s.getCustomConfig()

	// ############ STEP 1 Call /api/login without state or code
	// ############
	err := service.Login(authorizeCtx, login.NewLoginIdentityProvider(customConfig), customConfig)
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
	err = service.Login(authorizeCtx, login.NewLoginIdentityProvider(customConfig), customConfig)

	//  ############ STEP 4: Token generated and recieved as a param in the redirect
	//  ############ Validate that there was redirect recieved.
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

	require.NoError(s.T(), testtoken.EqualAccessTokenWithIdentity(context.Background(), *returnedToken.AccessToken, *s.identity))
}

func (s *serviceLoginBlackBoxTest) TestLoginEndToEndUnapproved() {
	idpServerURL := "http://" + s.IDPServer.Listener.Addr().String() + "/api/"
	prms := url.Values{}
	s.approved = false

	authorizeCtx, rw := s.createNewLoginContext("/api/login", prms)
	service := s.createNewLoginService()
	customConfig := s.getCustomConfig()

	// ############ STEP 1 Call /api/login without state or code
	// ############
	err := service.Login(authorizeCtx, login.NewLoginIdentityProvider(customConfig), customConfig)
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
	err = service.Login(authorizeCtx, login.NewLoginIdentityProvider(customConfig), customConfig)

	//  ############ STEP 4: Token generated and recieved as a param in the redirect
	//  ############ Validate that there was redirect recieved.
	require.Nil(s.T(), err)
	require.Equal(s.T(), 401, rw.Code)
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

		s.identity = s.Graph.CreateUser(s.Graph.ID("foo")).Identity()
		require.NotEmpty(s.T(), req.Referer())
		urlRef, err := url.Parse(req.Referer())
		require.NoError(s.T(), err)
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
		if err != nil {
			panic(err)
		}
		refreshToken, err := testtoken.GenerateRefreshTokenWithClaims(claims)
		if err != nil {
			panic(err)
		}
		expires_in := time.Now().Unix() + 60*60*24*30
		tokenResponse := fmt.Sprintf("{\"access_token\":\"%s\",\"refresh_token\":\"%s\",\"expires_in\":\"%s\",\"token_type\":\"%s\"", accessToken, refreshToken, strconv.FormatInt(expires_in, 10), "bearer")

		rw.Write([]byte(tokenResponse))
	} else if req.URL.Path == "/api/profile" {
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
		rw.Write(inBytes)
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

	refererUrl := "https://alm-url.example.org/path"
	req.Header.Add("referer", refererUrl)

	//prms := url.Values{"code": []string{"dfd"}}
	ctx := testtoken.ContextWithTokenManager()
	goaCtx := goa.NewContext(goa.WithAction(ctx, "LoginTest"), rw, req, prms)
	loginCtx, err := app.NewLoginLoginContext(goaCtx, req, goa.New("LoginService"))
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
