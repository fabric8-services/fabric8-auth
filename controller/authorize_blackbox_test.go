package controller_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
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
	clientID := "5dec5fdb-09e3-4453-b73f-5c828832b28e"
	responseType := "code"
	state := uuid.NewV4()

	test.AuthorizeAuthorizeTemporaryRedirect(t, svc.Context, svc, ctrl, nil, clientID, redirect, responseType, nil, state)
}

func (rest *TestAuthorizeREST) TestAuthorizeCallbackOK() {
	t := rest.T()
	_, ctrl := rest.UnSecuredController()

	rw := httptest.NewRecorder()
	u := &url.URL{
		Path: fmt.Sprintf("/api/authorize"),
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	require.Nil(t, err)

	redirectURI := "https://openshift.io/somepath"
	prms := url.Values{}

	prms.Add("response_type", "code")
	prms.Add("redirect_uri", redirectURI)
	prms.Add("client_id", "5dec5fdb-09e3-4453-b73f-5c828832b28e")
	prms.Add("state", uuid.NewV4().String())

	ctx := context.Background()
	goaCtx := goa.NewContext(goa.WithAction(ctx, "AuthorizeTest"), rw, req, prms)
	authorizeCtx, err := app.NewAuthorizeAuthorizeContext(goaCtx, req, goa.New("LoginService"))
	require.Nil(t, err)

	err = ctrl.Authorize(authorizeCtx)
	require.Nil(t, err)

	require.Equal(t, 307, rw.Code) // redirect to keycloak login page.

	locationString := rw.HeaderMap["Location"][0]
	locationUrl, err := url.Parse(locationString)
	require.Nil(t, err)

	allQueryParameters := locationUrl.Query()

	require.NotNil(t, allQueryParameters)
	require.NotNil(t, allQueryParameters["state"][0])

	returnedState := allQueryParameters["state"][0]

	u = &url.URL{
		Path: fmt.Sprintf("/api/authorize/callback"),
	}

	prms = url.Values{
		"state": {returnedState},
		"code":  {"SOME_OAUTH2.0_CODE"},
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

	require.Equal(t, 307, rw.Code) // redirect to keycloak login page.

	require.Contains(t, rw.Header().Get("Location"), redirectURI)

	locationString = rw.HeaderMap["Location"][0]
	locationUrl, err = url.Parse(locationString)
	require.Nil(t, err)

	allQueryParameters = locationUrl.Query()

	require.NotNil(t, allQueryParameters)
	require.NotNil(t, allQueryParameters["state"][0])
	require.NotNil(t, allQueryParameters["code"][0])
	require.Equal(t, returnedState, allQueryParameters["state"][0])
}

func (rest *TestAuthorizeREST) TestAuthorizeBadRequest() {
	t := rest.T()

	rw := httptest.NewRecorder()
	u := &url.URL{
		Path: fmt.Sprintf("/api/authorize"),
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	require.Nil(t, err)

	redirectURI := "https://openshift.io/somepath"
	prms := url.Values{}

	prms.Add("response_type", "code")
	prms.Add("redirect_uri", redirectURI)
	prms.Add("client_id", "5dec5fdb-09e3-4453-b73f-5c828832b28e")
	prms.Add("state", uuid.NewV4().String())

	ctx := context.Background()

	prms.Del("response_type")
	goaCtx := goa.NewContext(goa.WithAction(ctx, "AuthorizeTest"), rw, req, prms)
	authorizeCtx, err := app.NewAuthorizeAuthorizeContext(goaCtx, req, goa.New("LoginService"))
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "400 invalid_request: missing required parameter")
	jsonapi.JSONErrorResponse(authorizeCtx, err)
	require.Equal(t, 400, rw.Code)

	prms.Del("redirect_uri")
	goaCtx = goa.NewContext(goa.WithAction(ctx, "AuthorizeTest"), rw, req, prms)
	authorizeCtx, err = app.NewAuthorizeAuthorizeContext(goaCtx, req, goa.New("LoginService"))
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "400 invalid_request: missing required parameter")
	jsonapi.JSONErrorResponse(authorizeCtx, err)
	require.Equal(t, 400, rw.Code)

	prms.Del("client_id")
	goaCtx = goa.NewContext(goa.WithAction(ctx, "AuthorizeTest"), rw, req, prms)
	authorizeCtx, err = app.NewAuthorizeAuthorizeContext(goaCtx, req, goa.New("LoginService"))
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "400 invalid_request: missing required parameter")
	jsonapi.JSONErrorResponse(authorizeCtx, err)
	require.Equal(t, 400, rw.Code)

	prms.Del("state")
	goaCtx = goa.NewContext(goa.WithAction(ctx, "AuthorizeTest"), rw, req, prms)
	authorizeCtx, err = app.NewAuthorizeAuthorizeContext(goaCtx, req, goa.New("LoginService"))
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "400 invalid_request: missing required parameter")
	jsonapi.JSONErrorResponse(authorizeCtx, err)
	require.Equal(t, 400, rw.Code)
}

func (rest *TestAuthorizeREST) TestAuthorizeCallbackBadRequest() {
	t := rest.T()

	rw := httptest.NewRecorder()
	u := &url.URL{
		Path: fmt.Sprintf("/api/authorize/callback"),
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	require.Nil(t, err)

	prms := url.Values{}
	prms.Add("code", "SOME_OAUTH2.0_CODE")
	prms.Add("state", uuid.NewV4().String())

	ctx := context.Background()

	prms.Del("code")
	goaCtx := goa.NewContext(goa.WithAction(ctx, "AuthorizeTest"), rw, req, prms)
	callbackCtx, err := app.NewAuthorizeAuthorizeContext(goaCtx, req, goa.New("LoginService"))
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "400 invalid_request: missing required parameter")
	jsonapi.JSONErrorResponse(callbackCtx, err)
	require.Equal(t, 400, rw.Code)

	prms.Del("state")
	goaCtx = goa.NewContext(goa.WithAction(ctx, "AuthorizeTest"), rw, req, prms)
	_, err = app.NewAuthorizeAuthorizeContext(goaCtx, req, goa.New("LoginService"))
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "400 invalid_request: missing required parameter")
	jsonapi.JSONErrorResponse(callbackCtx, err)
	require.Equal(t, 400, rw.Code)
}
