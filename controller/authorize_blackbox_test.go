package controller_test

import (
	"context"
	"fmt"
	rand "math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/client"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	uuid "github.com/satori/go.uuid"

	"github.com/goadesign/goa"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestAuthorizeREST struct {
	gormtestsupport.DBTestSuite
}

func TestRunAuthorizeREST(t *testing.T) {
	suite.Run(t, &TestAuthorizeREST{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (rest *TestAuthorizeREST) UnSecuredController() (*goa.Service, *AuthorizeController) {
	svc := testsupport.ServiceAsUser("Login-Service", testsupport.TestIdentity)
	loginService := newTestKeycloakOAuthProvider(rest.Application)
	return svc, &AuthorizeController{Controller: svc.NewController("AuthorizeController"), Auth: loginService, Configuration: rest.Configuration}
}

func (rest *TestAuthorizeREST) TestAuthorizeOK() {
	t := rest.T()
	svc, ctrl := rest.UnSecuredController()

	redirect := "https://openshift.io"
	clientID := rest.Configuration.GetPublicOauthClientID()
	responseType := "code"
	state := uuid.NewV4().String()
	responseMode := "query"

	test.AuthorizeAuthorizeTemporaryRedirect(t, svc.Context, svc, ctrl, nil, clientID, redirect, &responseMode, responseType, nil, state)

	state = "not-uuid"
	test.AuthorizeAuthorizeTemporaryRedirect(t, svc.Context, svc, ctrl, nil, clientID, redirect, &responseMode, responseType, nil, state)

	state = uuid.NewV4().String()
	responseMode = "fragment"
	test.AuthorizeAuthorizeTemporaryRedirect(t, svc.Context, svc, ctrl, nil, clientID, redirect, &responseMode, responseType, nil, state)

	state = uuid.NewV4().String()
	test.AuthorizeAuthorizeTemporaryRedirect(t, svc.Context, svc, ctrl, nil, clientID, redirect, nil, responseType, nil, state)
}

func (rest *TestAuthorizeREST) TestAuthorizeBadRequest() {
	t := rest.T()

	u := &url.URL{
		Path: fmt.Sprintf(client.AuthorizeAuthorizePath()),
	}

	prms := url.Values{}
	prms.Add("response_type", "code")
	prms.Add("redirect_uri", "https://openshift.io/somepath")
	prms.Add("client_id", rest.Configuration.GetPublicOauthClientID())
	prms.Add("state", uuid.NewV4().String())

	rest.checkInvalidRequest("authorize", "response_type", prms, u, t)
	rest.checkInvalidRequest("authorize", "redirect_uri", prms, u, t)
	rest.checkInvalidRequest("authorize", "client_id", prms, u, t)
	rest.checkInvalidRequest("authorize", "state", prms, u, t)
}

func (rest *TestAuthorizeREST) TestAuthorizeUnauthorizedError() {
	t := rest.T()
	svc, ctrl := rest.UnSecuredController()

	redirect := "https://openshift.io"
	clientID := ""
	responseType := "code"
	state := uuid.NewV4().String()

	test.AuthorizeAuthorizeUnauthorized(t, svc.Context, svc, ctrl, nil, clientID, redirect, nil, responseType, nil, state)
}

func (rest *TestAuthorizeREST) TestAuthorizeCallbackOK() {
	rest.checkAuthorizeCallbackOK(nil)
	responseMode := "query"
	rest.checkAuthorizeCallbackOK(&responseMode)
	responseMode = "fragment"
	rest.checkAuthorizeCallbackOK(&responseMode)
}

func (rest *TestAuthorizeREST) checkAuthorizeCallbackOK(responseMode *string) {
	t := rest.T()
	_, ctrl := rest.UnSecuredController()

	rw := httptest.NewRecorder()
	u := &url.URL{
		Path: fmt.Sprintf(client.AuthorizeAuthorizePath()),
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	require.Nil(t, err)

	redirectURI := "https://openshift.io/somepath"
	prms := url.Values{}
	prms.Add("response_type", "code")
	prms.Add("redirect_uri", redirectURI)
	prms.Add("client_id", rest.Configuration.GetPublicOauthClientID())
	prms.Add("state", uuid.NewV4().String())
	if responseMode != nil {
		prms.Add("response_mode", *responseMode)
	}
	ctx := context.Background()
	goaCtx := goa.NewContext(goa.WithAction(ctx, "AuthorizeTest"), rw, req, prms)
	authorizeCtx, err := app.NewAuthorizeAuthorizeContext(goaCtx, req, goa.New("LoginService"))
	require.Nil(t, err)

	err = ctrl.Authorize(authorizeCtx)
	require.Nil(t, err)

	require.Equal(t, 307, rw.Code) // redirect to keycloak login page.

	locationString := rw.HeaderMap["Location"][0]
	authEndpoint, _ := rest.Configuration.GetKeycloakEndpointAuth(authorizeCtx.RequestData)
	require.Contains(t, locationString, authEndpoint)
	locationUrl, err := url.Parse(locationString)
	require.Nil(t, err)

	allQueryParameters := locationUrl.Query()

	require.NotNil(t, allQueryParameters)
	require.NotNil(t, allQueryParameters["state"][0])
	returnedState := allQueryParameters["state"][0]

	u = &url.URL{
		Path: fmt.Sprintf(client.CallbackAuthorizePath()),
	}

	code := strconv.Itoa(rand.Int())
	prms = url.Values{
		"state": {returnedState},
		"code":  {code},
	}

	ctx = context.Background()
	rw = httptest.NewRecorder()

	req, err = http.NewRequest("GET", u.String(), nil)
	require.Nil(t, err)

	// The OAuth code is sent as a query parameter by calling /api/login?code=_SOME_CODE_&state=_SOME_STATE_
	// The request originates from Keycloak after a valid authorization by the end user.
	refererKeycloakUrl := "https://keycloak-url.example.org/path-of-login"
	req.Header.Add("referer", refererKeycloakUrl)

	goaCtx = goa.NewContext(goa.WithAction(ctx, "AuthorizecallbackTest"), rw, req, prms)
	callbackCtx, err := app.NewCallbackAuthorizeContext(goaCtx, req, goa.New("LoginService"))
	require.Nil(t, err)

	err = ctrl.Callback(callbackCtx)
	require.Nil(t, err)

	require.Equal(t, 307, rw.Code)

	locationString = rw.HeaderMap["Location"][0]
	locationUrl, err = url.Parse(locationString)
	require.True(t, strings.HasPrefix(locationString, redirectURI))
	require.Nil(t, err)

	if responseMode == nil || *responseMode != "fragment" {
		require.NotNil(t, locationUrl.RawQuery)
		allQueryParameters = locationUrl.Query()

		require.NotNil(t, allQueryParameters)
		require.NotNil(t, allQueryParameters["state"][0])
		require.Equal(t, returnedState, allQueryParameters["state"][0])
		require.NotNil(t, allQueryParameters["code"][0])
		require.Equal(t, code, allQueryParameters["code"][0])
	} else {
		require.NotNil(t, locationUrl.Fragment)
		require.True(t, strings.HasPrefix(locationUrl.Fragment, "code"))
		require.Contains(t, locationUrl.Fragment, "state")
	}
}
func (rest *TestAuthorizeREST) TestAuthorizeCallbackBadRequest() {
	t := rest.T()

	u := &url.URL{
		Path: fmt.Sprintf(client.CallbackAuthorizePath()),
	}

	prms := url.Values{}
	prms.Add("code", "SOME_OAUTH2.0_CODE")
	prms.Add("state", uuid.NewV4().String())

	rest.checkInvalidRequest("authorizeCallback", "code", prms, u, t)
	rest.checkInvalidRequest("authorizeCallback", "state", prms, u, t)
}

func (rest *TestAuthorizeREST) TestAuthorizeCallbackUnauthorizedError() {
	t := rest.T()
	_, ctrl := rest.UnSecuredController()

	rw := httptest.NewRecorder()
	u := &url.URL{
		Path: fmt.Sprintf(client.AuthorizeAuthorizePath()),
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	require.Nil(t, err)

	redirectURI := "https://openshift.io/somepath"
	prms := url.Values{}

	state := uuid.NewV4().String()
	prms.Add("response_type", "code")
	prms.Add("redirect_uri", redirectURI)
	prms.Add("client_id", rest.Configuration.GetPublicOauthClientID())
	prms.Add("state", state)

	ctx := context.Background()
	goaCtx := goa.NewContext(goa.WithAction(ctx, "AuthorizeTest"), rw, req, prms)
	authorizeCtx, err := app.NewAuthorizeAuthorizeContext(goaCtx, req, goa.New("LoginService"))
	require.Nil(t, err)

	err = ctrl.Authorize(authorizeCtx)
	require.Nil(t, err)

	require.Equal(t, 307, rw.Code) // redirect to keycloak login page.

	locationString := rw.HeaderMap["Location"][0]
	authEndpoint, _ := rest.Configuration.GetKeycloakEndpointAuth(authorizeCtx.RequestData)
	require.Contains(t, locationString, authEndpoint)
	locationUrl, err := url.Parse(locationString)
	require.Nil(t, err)

	allQueryParameters := locationUrl.Query()

	require.NotNil(t, allQueryParameters)
	require.NotNil(t, allQueryParameters["state"][0])
	require.Equal(t, state, allQueryParameters["state"][0])

	u = &url.URL{
		Path: fmt.Sprintf(client.CallbackAuthorizePath()),
	}

	prms = url.Values{
		"state": {uuid.NewV4().String()},
		"code":  {"SOME_OAUTH2.0_CODE"},
	}

	// Request with wrong state results in unauthorized error
	statusCode, err := rest.makeNewRequest("authorizeCallback", u, t, prms, ctrl)
	require.NotNil(t, err)
	require.Equal(t, 401, statusCode)

	// Correct state results in success thus redirect state and code to redirecURI/referrer resulting in statusCode 307
	prms.Set("state", state)
	statusCode, err = rest.makeNewRequest("authorizeCallback", u, t, prms, ctrl)
	require.Nil(t, err)
	require.Equal(t, 307, statusCode)

	// Call the same call back one more time to make sure it now fails (because the corresponding state does not exist anymore).
	statusCode, err = rest.makeNewRequest("authorizeCallback", u, t, prms, ctrl)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "No encoder registered for  and no default encoder")
	require.Equal(t, 401, statusCode)
}

func (rest *TestAuthorizeREST) checkInvalidRequest(testFor string, toBeRemoved string, prms url.Values, u *url.URL, t *testing.T) {
	ctx := context.Background()
	rw := httptest.NewRecorder()

	req, err := http.NewRequest("GET", u.String(), nil)
	require.Nil(t, err)

	// The OAuth code is sent as a query parameter by calling /api/login?code=_SOME_CODE_&state=_SOME_STATE_
	// The request originates from Keycloak after a valid authorization by the end user.
	refererKeycloakUrl := "https://keycloak-url.example.org/path-of-login"
	req.Header.Add("referer", refererKeycloakUrl)

	valueToAdd := prms.Get(toBeRemoved)
	prms.Del(toBeRemoved)
	goaCtx := goa.NewContext(goa.WithAction(ctx, "AuthorizeTest"), rw, req, prms)
	if testFor == "authorize" {
		authorizeCtx, err := app.NewAuthorizeAuthorizeContext(goaCtx, req, goa.New("LoginService"))
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "400 invalid_request: missing required parameter")
		jsonapi.JSONErrorResponse(authorizeCtx, err)
	}

	if testFor == "authorizeCallback" {
		callbackCtx, err := app.NewCallbackAuthorizeContext(goaCtx, req, goa.New("LoginService"))
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "400 invalid_request: missing required parameter")
		jsonapi.JSONErrorResponse(callbackCtx, err)
	}

	require.Equal(t, 400, rw.Code)
	prms.Add(toBeRemoved, valueToAdd)
}

// for a request to /authorize/callback use testFor = "authorizeCallback" and anything else for a request to /authorize
func (rest *TestAuthorizeREST) makeNewRequest(testFor string, u *url.URL, t *testing.T, prms url.Values, ctrl *AuthorizeController) (int, error) {
	ctx := context.Background()
	rw := httptest.NewRecorder()

	req, err := http.NewRequest("GET", u.String(), nil)
	require.Nil(t, err)

	// The OAuth code is sent as a query parameter by calling /api/login?code=_SOME_CODE_&state=_SOME_STATE_
	// The request originates from Keycloak after a valid authorization by the end user.
	refererKeycloakUrl := "https://keycloak-url.example.org/path-of-login"
	req.Header.Add("referer", refererKeycloakUrl)

	goaCtx := goa.NewContext(goa.WithAction(ctx, "AuthorizeTest"), rw, req, prms)
	if testFor == "authorizeCallback" {
		callbackCtx, err := app.NewCallbackAuthorizeContext(goaCtx, req, goa.New("LoginService"))
		require.Nil(t, err)
		err = ctrl.Callback(callbackCtx)
		return rw.Code, err
	}

	authorizeCtx, err := app.NewAuthorizeAuthorizeContext(goaCtx, req, goa.New("LoginService"))
	require.Nil(t, err)
	err = ctrl.Authorize(authorizeCtx)
	return rw.Code, err
}
