package login_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/goadesign/goa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	_ "github.com/lib/pq"
)

func TestLogout(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	config, err := configuration.GetConfigurationData()
	if err != nil {
		panic(fmt.Errorf("Failed to setup the configuration: %s", err.Error()))
	}
	suite.Run(t, &TestLogoutSuite{config: config, logoutService: &login.KeycloakLogoutService{}})
}

type TestLogoutSuite struct {
	suite.Suite
	config        *configuration.ConfigurationData
	logoutService *login.KeycloakLogoutService
}

func (s *TestLogoutSuite) SetupSuite() {
}

func (s *TestLogoutSuite) TearDownSuite() {
}

func (s *TestLogoutSuite) TestLogoutRedirectsToKeycloakWithRedirectParam() {
	s.checkRedirects("https://openshift.io/home", "", "https%3A%2F%2Fopenshift.io%2Fhome")
}

func (s *TestLogoutSuite) TestLogoutRedirectsToKeycloakWithReferrer() {
	s.checkRedirects("", "https://openshift.io/home", "https%3A%2F%2Fopenshift.io%2Fhome")
}

func (s *TestLogoutSuite) TestLogoutRedirectsToKeycloakWithReferrerAndRedirect() {
	s.checkRedirects("https://prod-preview.openshift.io/home", "https://url.example.org/path", "https%3A%2F%2Fprod-preview.openshift.io%2Fhome")
}

func (s *TestLogoutSuite) TestLogoutRedirectsToKeycloakWithInvalidRedirectParamBadRequest() {
	s.checkRedirects("https://url.example.org/path", "", "")
}

func (s *TestLogoutSuite) TestLogoutRedirectsToKeycloakWithInvalidReferrerParamBadRequest() {
	s.checkRedirects("", "https://url.example.org/path", "")
}

func (s *TestLogoutSuite) TestLogoutRedirectsToKeycloakWithReferrerAndInvalidRedirectBadRequest() {
	s.checkRedirects("https://url.example.org/path", "https://openshift.io/home", "")
}

func (s *TestLogoutSuite) checkRedirects(redirectParam string, referrerURL string, expectedRedirectParam string) {
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

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.domain.io"},
	}
	logoutEndpoint, err := s.config.GetKeycloakEndpointLogout(r)
	require.Nil(s.T(), err)
	validURLs := configuration.DefaultValidRedirectURLs

	err = s.logoutService.Logout(logoutCtx, logoutEndpoint, validURLs)
	require.NoError(s.T(), err)

	if expectedRedirectParam == "" {
		assert.Equal(s.T(), 400, rw.Code)
	} else {
		assert.Equal(s.T(), 307, rw.Code)
		assert.Equal(s.T(), fmt.Sprintf("%s?redirect_uri=%s", logoutEndpoint, expectedRedirectParam), rw.Header().Get("Location"))
	}
}
