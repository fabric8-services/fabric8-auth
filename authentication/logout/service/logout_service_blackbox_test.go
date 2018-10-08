package service_test

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/goadesign/goa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type logoutServiceBlackBoxTest struct {
	gormtestsupport.DBTestSuite
}

func TestRunLogoutServiceBlackBoxTest(t *testing.T) {
	suite.Run(t, &logoutServiceBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *logoutServiceBlackBoxTest) TestLogoutRedirectsWithRedirectParam() {
	s.checkRedirects("https://openshift.io/home", "", "https%3A%2F%2Fopenshift.io%2Fhome")
}

func (s *logoutServiceBlackBoxTest) TestLogoutRedirectsWithReferrer() {
	s.checkRedirects("", "https://openshift.io/home", "https%3A%2F%2Fopenshift.io%2Fhome")
}

func (s *logoutServiceBlackBoxTest) TestLogoutRedirectsWithReferrerAndRedirect() {
	s.checkRedirects("https://prod-preview.openshift.io/home", "https://url.example.org/path", "https%3A%2F%2Fprod-preview.openshift.io%2Fhome")
}

func (s *logoutServiceBlackBoxTest) TestLogoutRedirectsWithInvalidRedirectParamBadRequest() {
	s.checkRedirects("https://url.example.org/path", "", "")
}

func (s *logoutServiceBlackBoxTest) TestLogoutRedirectsWithInvalidReferrerParamBadRequest() {
	s.checkRedirects("", "https://url.example.org/path", "")
}

func (s *logoutServiceBlackBoxTest) TestLogoutRedirectsWithReferrerAndInvalidRedirectBadRequest() {
	s.checkRedirects("https://url.example.org/path", "https://openshift.io/home", "")
}

func (s *logoutServiceBlackBoxTest) checkRedirects(redirectParam string, referrerURL string, expectedRedirectParam string) {
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

	s.Application.LogoutService().Logout(logoutCtx, expectedRedirectParam)

	if expectedRedirectParam == "" {
		assert.Equal(s.T(), 400, rw.Code)
	} else {
		assert.Equal(s.T(), 307, rw.Code)
		assert.Equal(s.T(), expectedRedirectParam, rw.Header().Get("Location"))
	}
}
