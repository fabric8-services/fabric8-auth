package login_test

import (
	"context"
	"errors"
	"golang.org/x/oauth2"
	"net/http"
	"testing"

	"github.com/fabric8-services/fabric8-auth/configuration"
	autherrors "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/test"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"
	"github.com/fabric8-services/fabric8-auth/test/token"

	"bytes"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"io/ioutil"
)

type TestOSORegistrationAppSuite struct {
	testsuite.UnitTestSuite
	osoApp      login.OSOSubscriptionManager
	client      *dummyOSOClient
	loginConfig login.Configuration
}

func TestOSORegistrationApp(t *testing.T) {
	suite.Run(t, &TestOSORegistrationAppSuite{UnitTestSuite: testsuite.NewUnitTestSuite()})
}

func (s *TestOSORegistrationAppSuite) SetupSuite() {
	s.UnitTestSuite.SetupSuite()
	s.client = &dummyOSOClient{suite: s}
	s.osoApp = login.NewOSORegistrationAppWithClient(s.client)
	s.loginConfig = &dummyConfig{s.Config}
}

// Fails if there is no token manager in the context
func (s *TestOSORegistrationAppSuite) TestNoTokenManagerInContextFails() {
	_, err := s.osoApp.LoadOSOSubscriptionStatus(context.Background(), s.loginConfig, oauth2.Token{})
	require.Error(s.T(), err)
}

// Fails if the token is invalid
func (s *TestOSORegistrationAppSuite) TestInvalidTokeFails() {
	_, err := s.osoApp.LoadOSOSubscriptionStatus(token.ContextWithTokenManager(), s.loginConfig, oauth2.Token{})
	require.Error(s.T(), err)
}

func (s *TestOSORegistrationAppSuite) TestClientResponse() {
	accessToken, err := token.GenerateToken(uuid.NewV4().String(), "test-oso-registration-app-user")
	require.NoError(s.T(), err)

	// Should return an error if the client failed
	s.client.Error = errors.New("something went wrong")
	_, err = s.osoApp.LoadOSOSubscriptionStatus(token.ContextWithTokenManager(), s.loginConfig, oauth2.Token{AccessToken: accessToken})
	require.Error(s.T(), err)
	assert.IsType(s.T(), autherrors.InternalError{}, err)

	// Should return an error if the client returns any status but 200 or 404
	s.client.Error = nil
	body := ioutil.NopCloser(bytes.NewReader([]byte{}))
	s.client.Response = &http.Response{Body: body, StatusCode: http.StatusInternalServerError}
	_, err = s.osoApp.LoadOSOSubscriptionStatus(token.ContextWithTokenManager(), s.loginConfig, oauth2.Token{AccessToken: accessToken})
	require.Error(s.T(), err)
	assert.IsType(s.T(), autherrors.InternalError{}, err)

	// Should return "signup_needed" if the client returns 404
	s.client.Response = &http.Response{Body: body, StatusCode: http.StatusNotFound}
	status, err := s.osoApp.LoadOSOSubscriptionStatus(token.ContextWithTokenManager(), s.loginConfig, oauth2.Token{AccessToken: accessToken})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "signup_needed", status)

	// Should return an error if the client returns invalid payload
	body = ioutil.NopCloser(bytes.NewReader([]byte("foo")))
	s.client.Response = &http.Response{Body: body, StatusCode: http.StatusOK}
	_, err = s.osoApp.LoadOSOSubscriptionStatus(token.ContextWithTokenManager(), s.loginConfig, oauth2.Token{AccessToken: accessToken})
	require.Error(s.T(), err)
	assert.IsType(s.T(), autherrors.InternalError{}, err)

	// Should return "signup_needed" if no subscription found
	body = ioutil.NopCloser(bytes.NewReader([]byte("{\"subscriptions\":[{\"status\":\"some-test-status\",\"plan\":{\"service\":{\"api_url\":\"unknown_cluster\"}}}]}")))
	s.client.Response = &http.Response{Body: body, StatusCode: http.StatusOK}
	status, err = s.osoApp.LoadOSOSubscriptionStatus(token.ContextWithTokenManager(), s.loginConfig, oauth2.Token{AccessToken: accessToken})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "signup_needed", status)

	// Subscription found
	body = ioutil.NopCloser(bytes.NewReader([]byte("{\"subscriptions\":[{\"status\":\"some-test-status-for2\",\"plan\":{\"service\":{\"api_url\":\"https://api.starter-us-east-2a.openshift.com/\"}}}]}")))
	s.client.Response = &http.Response{Body: body, StatusCode: http.StatusOK}
	status, err = s.osoApp.LoadOSOSubscriptionStatus(token.ContextWithTokenManager(), s.loginConfig, oauth2.Token{AccessToken: accessToken})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "some-test-status-for2", status)

	// Multiple subscriptions
	body = ioutil.NopCloser(bytes.NewReader([]byte("{\"subscriptions\":[{\"status\":\"some-test-status\",\"plan\":{\"service\":{\"api_url\":\"unknown_cluster\"}}},{\"status\":\"some-test-status-for2\",\"plan\":{\"service\":{\"api_url\":\"https://api.starter-us-east-2a.openshift.com/\"}}},{\"status\":\"some-test-status\",\"plan\":{\"service\":{\"api_url\":\"unknown_cluster\"}}}]}")))
	s.client.Response = &http.Response{Body: body, StatusCode: http.StatusOK}
	status, err = s.osoApp.LoadOSOSubscriptionStatus(token.ContextWithTokenManager(), s.loginConfig, oauth2.Token{AccessToken: accessToken})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "some-test-status-for2", status)
}

type dummyOSOClient struct {
	test.DummyHttpClient
	suite *TestOSORegistrationAppSuite
}

func (c *dummyOSOClient) Do(req *http.Request) (*http.Response, error) {
	require.Equal(c.suite.T(), "GET", req.Method)
	require.Equal(c.suite.T(), "https://some.osourl.io/api/accounts/test-oso-registration-app-user/subscriptions?authorization_username=test-oso-admin-user", req.URL.String())
	require.Equal(c.suite.T(), "Bearer test-oso-admin-token", req.Header.Get("Authorization"))
	return c.Response, c.Error
}

type dummyConfig struct {
	*configuration.ConfigurationData
}

func (c *dummyConfig) GetOSORegistrationAppURL() string {
	return "https://some.osourl.io"
}

func (c *dummyConfig) GetOSORegistrationAppAdminUsername() string {
	return "test-oso-admin-user"
}

func (c *dummyConfig) GetOSORegistrationAppAdminToken() string {
	return "test-oso-admin-token"
}
