package controller_test

import (
	"github.com/fabric8-services/fabric8-auth/authorization/token"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"testing"

	"context"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/stretchr/testify/require"

	"github.com/fabric8-services/fabric8-auth/resource"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"

	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type LogoutControllerTestSuite struct {
	gormtestsupport.DBTestSuite
}

func TestLogoutControllerTestSuite(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &LogoutControllerTestSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *LogoutControllerTestSuite) UnsecuredController() (*goa.Service, *controller.LogoutController) {
	svc := goa.New("Logout-Service")
	controller := controller.NewLogoutController(svc, s.Application)
	return svc, controller
}

func (s *LogoutControllerTestSuite) SecuredController() (*goa.Service, *controller.LogoutController, account.Identity) {
	identity, err := testsupport.CreateTestIdentity(s.DB, uuid.NewV4().String(), "KC")
	require.Nil(s.T(), err)
	svc, ctrl := s.SecuredControllerWithIdentity(identity)
	return svc, ctrl, identity
}

func (s *LogoutControllerTestSuite) SecuredControllerWithIdentity(identity account.Identity) (*goa.Service, *controller.LogoutController) {
	svc := testsupport.ServiceAsUser("Logout-Service", identity)
	return svc, controller.NewLogoutController(svc, s.Application)
}


func (s *LogoutControllerTestSuite) TestLogout() {

	user := s.Graph.CreateUser()

	s.T().Run("redirect", func(t *testing.T) {

		t.Run("with redirect param only", func(t *testing.T) {
			// given
			svc, ctrl := s.SecuredControllerWithIdentity(*user.Identity())
			redirect := "https://openshift.io/home"
			// when
			resp := test.LogoutLogoutTemporaryRedirect(s.T(), svc.Context, svc, ctrl, &redirect, nil)
			// then
			assert.Equal(t, resp.Header().Get("Cache-Control"), "no-cache")
			assert.Equal(t, "https://sso.prod-preview.openshift.io/auth/realms/fabric8-test/protocol/openid-connect/logout?redirect_uri=https%3A%2F%2Fopenshift.io%2Fhome", resp.Header().Get("Location"))
		})

		t.Run("with referer header only", func(t *testing.T) {
			// given
			svc, ctrl := s.UnsecuredController()
			referer := "https://openshift.io/home"
			// when
			resp := test.LogoutLogoutTemporaryRedirect(s.T(), svc.Context, svc, ctrl, nil, &referer)
			// then
			assert.Equal(t, resp.Header().Get("Cache-Control"), "no-cache")
			assert.Contains(t, resp.Header().Get("Location"), "?redirect_uri=https%3A%2F%2Fopenshift.io%2Fhome")
		})

		t.Run("with redirect param and referer header", func(t *testing.T) {
			// given
			svc, ctrl := s.UnsecuredController()
			redirect := "https://prod-preview.openshift.io/home"
			referer := "https://url.example.org/path"
			// when
			resp := test.LogoutLogoutTemporaryRedirect(s.T(), svc.Context, svc, ctrl, &redirect, &referer)
			// then
			assert.Equal(t, resp.Header().Get("Cache-Control"), "no-cache")
			assert.Contains(t, resp.Header().Get("Location"), "?redirect_uri=https%3A%2F%2Fprod-preview.openshift.io%2Fhome")
		})
	})

	s.T().Run("bad request", func(t *testing.T) {

		t.Run("with missing referer and redirect", func(t *testing.T) {
			// given
			svc, ctrl := s.UnsecuredController()
			// when/then
			test.LogoutLogoutBadRequest(t, svc.Context, svc, ctrl, nil, nil)
		})

		t.Run("with missing referer header and redirect param", func(t *testing.T) {
			// given
			svc, ctrl := s.UnsecuredController()
			// when/then
			test.LogoutLogoutBadRequest(t, svc.Context, svc, ctrl, nil, nil)
		})

		t.Run("with invalid redirect param", func(t *testing.T) {
			// given
			svc, ctrl := s.UnsecuredController()
			redirect := "://url.example.org/path" // invalid/unparseable URL
			referer := ""
			// when/then
			test.LogoutLogoutBadRequest(t, svc.Context, svc, ctrl, &redirect, &referer)
		})

		t.Run("with invalid referer header", func(t *testing.T) {
			// given
			svc, ctrl := s.UnsecuredController()
			redirect := ""
			referer := "://url.example.org/path" // invalid/unparseable URL
			// when/then
			test.LogoutLogoutBadRequest(t, svc.Context, svc, ctrl, &redirect, &referer)
		})

		t.Run("with redirect param and invalid referer header", func(t *testing.T) {
			t.Skipf("if redirect param is valid, then referer URL is not used")
			// given
			svc, ctrl := s.UnsecuredController()
			redirect := "https://url.example.org/path"
			referer := "://url.example.org/path" // invalid/unparseable URL
			// when/then
			test.LogoutLogoutBadRequest(t, svc.Context, svc, ctrl, &redirect, &referer)
		})
	})
}

func (s *LogoutControllerTestSuite) TestLogoutV2PayloadOK() {
	svc := testsupport.UnsecuredService("Logout-Service")
	ctrl := controller.NewLogoutController(svc, s.Application)

	redirect := "https://openshift.io/home"

	resp, redirectLocation := test.Logoutv2LogoutOK(s.T(), svc.Context, svc, ctrl, &redirect, nil)

	// then
	assert.Equal(s.T(), resp.Header().Get("Cache-Control"), "no-cache")
	assert.Equal(s.T(), "https://sso.prod-preview.openshift.io/auth/realms/fabric8-test/protocol/openid-connect/logout?redirect_uri=https%3A%2F%2Fopenshift.io%2Fhome",
		redirectLocation.RedirectLocation)
}

func (s *LogoutControllerTestSuite) TestLogoutV2TokensInvalidated() {
	tm := testtoken.TokenManager
	ctx := manager.ContextWithTokenManager(testtoken.ContextWithRequest(context.Background()), tm)
	// create a user
	user := s.Graph.CreateUser()
	// Create an initial access token for the user
	at, err := tm.GenerateUserTokenForIdentity(ctx, *user.Identity(), false)
	require.NoError(s.T(), err)
	// create space
	space := s.Graph.CreateSpace().AddAdmin(user)
	// create RPT for the space
	rptToken, err := s.Application.TokenService().Audit(ctx, user.Identity(), at.AccessToken, space.SpaceID())
	require.NoError(s.T(), err)

	tokenClaims, err := tm.ParseToken(ctx, *rptToken)
	require.NoError(s.T(), err)

	tokenID, err := uuid.FromString(tokenClaims.Id)
	require.NoError(s.T(), err)

	// Check there is a token registered for the user
	loadedToken, err := s.Application.TokenRepository().Load(s.Ctx, tokenID)
	require.NoError(s.T(), err)

	// And check the token has the correct status, type and identity
	require.Equal(s.T(), 0, loadedToken.Status)
	require.Equal(s.T(), token.TOKEN_TYPE_RPT, loadedToken.TokenType)
	require.Equal(s.T(), user.IdentityID(), loadedToken.IdentityID)

	tk, err := tm.Parse(s.Ctx, *rptToken)
	require.NoError(s.T(), err)

	svc := testsupport.ServiceAsUser("Logout-Service", *user.Identity())
	ctrl := controller.NewLogoutController(svc, s.Application)

	redirect := "https://openshift.io/home"

	test.Logoutv2LogoutOK(s.T(), goajwt.WithJWT(svc.Context, tk), svc, ctrl, &redirect, nil)

	// Load the token again
	loadedToken, err = s.Application.TokenRepository().Load(s.Ctx, tokenID)
	require.NoError(s.T(), err)

	// Now check that the status is logged out
	require.True(s.T(), loadedToken.HasStatus(token.TOKEN_STATUS_LOGGED_OUT))
}

func (s *LogoutControllerTestSuite) checkRedirects(redirectParam string, referrerURL string, expectedRedirectParam string) {
	rw := httptest.NewRecorder()
	u := &url.URL{
		Path: "/api/logout",
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	require.Nil(s.T(), err)
	if referrerURL != "" {
		req.Header.Add("referer", referrerURL)
	}

	prms := url.Values{}
	if redirectParam != "" {
		prms.Add("redirect", redirectParam)
	}
	ctx := context.Background()
	goaCtx := goa.NewContext(goa.WithAction(ctx, "LogoutTest"), rw, req, prms)
	logoutCtx, err := app.NewLogoutLogoutContext(goaCtx, req, goa.New("LogoutService"))
	require.Nil(s.T(), err)

	svc, ctrl := s.UnsecuredController()

	test.LogoutLogoutTemporaryRedirect(s.T(), logoutCtx, svc, ctrl, &expectedRedirectParam, nil)

	if expectedRedirectParam == "" {
		assert.Equal(s.T(), 400, rw.Code)
	} else {
		assert.Equal(s.T(), 307, rw.Code)
		assert.Equal(s.T(), expectedRedirectParam, rw.Header().Get("Location"))
	}
}
