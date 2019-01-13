package controller_test

import (
	"testing"

	"context"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/stretchr/testify/require"

	"github.com/fabric8-services/fabric8-auth/resource"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/goadesign/goa"
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

func (s *LogoutControllerTestSuite) UnSecuredController() (*goa.Service, *controller.LogoutController) {
	svc := testsupport.ServiceAsUser("Logout-Service", testsupport.TestIdentity)
	return svc, controller.NewLogoutController(svc, s.Application)
}

func (s *LogoutControllerTestSuite) TestLogout() {

	s.T().Run("redirect", func(t *testing.T) {

		t.Run("with redirect param only", func(t *testing.T) {
			// given
			svc, ctrl := s.UnSecuredController()
			redirect := "https://openshift.io/home"
			// when
			resp := test.LogoutLogoutTemporaryRedirect(s.T(), svc.Context, svc, ctrl, &redirect, nil)
			// then
			assert.Equal(t, resp.Header().Get("Cache-Control"), "no-cache")
			assert.Equal(t, "https://sso.prod-preview.openshift.io/auth/realms/fabric8-test/protocol/openid-connect/logout?redirect_uri=https%3A%2F%2Fopenshift.io%2Fhome", resp.Header().Get("Location"))
		})

		t.Run("with referer header only", func(t *testing.T) {
			// given
			svc, ctrl := s.UnSecuredController()
			referer := "https://openshift.io/home"
			// when
			resp := test.LogoutLogoutTemporaryRedirect(s.T(), svc.Context, svc, ctrl, nil, &referer)
			// then
			assert.Equal(t, resp.Header().Get("Cache-Control"), "no-cache")
			assert.Contains(t, resp.Header().Get("Location"), "?redirect_uri=https%3A%2F%2Fopenshift.io%2Fhome")
		})

		t.Run("with redirect param and referer header", func(t *testing.T) {
			// given
			svc, ctrl := s.UnSecuredController()
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
			svc, ctrl := s.UnSecuredController()
			// when/then
			test.LogoutLogoutBadRequest(t, svc.Context, svc, ctrl, nil, nil)
		})

		t.Run("with missing referer header and redirect param", func(t *testing.T) {
			// given
			svc, ctrl := s.UnSecuredController()
			// when/then
			test.LogoutLogoutBadRequest(t, svc.Context, svc, ctrl, nil, nil)
		})

		t.Run("with invalid redirect param", func(t *testing.T) {
			// given
			svc, ctrl := s.UnSecuredController()
			redirect := "://url.example.org/path" // invalid/unparseable URL
			referer := ""
			// when/then
			test.LogoutLogoutBadRequest(t, svc.Context, svc, ctrl, &redirect, &referer)
		})

		t.Run("with invalid referer header", func(t *testing.T) {
			// given
			svc, ctrl := s.UnSecuredController()
			redirect := ""
			referer := "://url.example.org/path" // invalid/unparseable URL
			// when/then
			test.LogoutLogoutBadRequest(t, svc.Context, svc, ctrl, &redirect, &referer)
		})

		t.Run("with redirect param and invalid referer header", func(t *testing.T) {
			t.Skipf("if redirect param is valid, then referer URL is not used")
			// given
			svc, ctrl := s.UnSecuredController()
			redirect := "https://url.example.org/path"
			referer := "://url.example.org/path" // invalid/unparseable URL
			// when/then
			test.LogoutLogoutBadRequest(t, svc.Context, svc, ctrl, &redirect, &referer)
		})
	})
}

func (s *LogoutControllerTestSuite) TestLogoutV2() {

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

	svc, ctrl := s.UnSecuredController()

	test.LogoutLogoutTemporaryRedirect(s.T(), logoutCtx, svc, ctrl, &expectedRedirectParam, nil)

	if expectedRedirectParam == "" {
		assert.Equal(s.T(), 400, rw.Code)
	} else {
		assert.Equal(s.T(), 307, rw.Code)
		assert.Equal(s.T(), expectedRedirectParam, rw.Header().Get("Location"))
	}
}
