package service_test

import (
	"bytes"
	"context"
	"errors"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/factory"
	"github.com/fabric8-services/fabric8-auth/configuration"
	autherrors "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/test"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type osoSubscriptionServiceTestSuite struct {
	gormtestsupport.DBTestSuite
	client             *test.DummyHttpClient
	clusterServiceMock service.ClusterService
}

func TestOSORegistrationApp(t *testing.T) {
	suite.Run(t, &osoSubscriptionServiceTestSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *osoSubscriptionServiceTestSuite) SetupSuite() {
	s.DBTestSuite.SetupSuite()

	s.clusterServiceMock = testsupport.NewClusterServiceMock(s.T())
	s.Application = gormapplication.NewGormDB(s.DB, s.Configuration, s.Wrappers, factory.WithClusterService(s.clusterServiceMock))

	s.client = &test.DummyHttpClient{AssertRequest: func(req *http.Request) {
		assert.Equal(s.T(), "GET", req.Method)
		assert.Equal(s.T(), "https://some.osourl.io/api/accounts/test-oso-registration-app-user/subscriptions?authorization_username=test-oso-admin-user", req.URL.String())
		assert.Equal(s.T(), "Bearer test-oso-admin-token", req.Header.Get("Authorization"))
	}}

}

// Fails if there is no token manager in the context
func (s *osoSubscriptionServiceTestSuite) TestNoTokenManagerInContextFails() {
	_, err := s.Application.OSOSubscriptionService().LoadOSOSubscriptionStatus(context.Background(), oauth2.Token{})
	require.Error(s.T(), err)
}

// Fails if the token is invalid
func (s *osoSubscriptionServiceTestSuite) TestInvalidTokeFails() {
	_, err := s.Application.OSOSubscriptionService().LoadOSOSubscriptionStatus(testtoken.ContextWithTokenManager(), oauth2.Token{})
	require.Error(s.T(), err)
}

func (s *osoSubscriptionServiceTestSuite) TestClientResponse() {
	accessToken, err := testtoken.GenerateToken(uuid.NewV4().String(), "test-oso-registration-app-user")
	require.NoError(s.T(), err)

	// Should return an error if the client failed
	s.client.Error = errors.New("something went wrong")
	_, err = s.Application.OSOSubscriptionService().LoadOSOSubscriptionStatus(testtoken.ContextWithTokenManager(), oauth2.Token{AccessToken: accessToken})
	require.Error(s.T(), err)
	assert.IsType(s.T(), autherrors.InternalError{}, err)

	// Should return an error if the client returns any status but 200 or 404
	s.client.Error = nil
	body := ioutil.NopCloser(bytes.NewReader([]byte{}))
	s.client.Response = &http.Response{Body: body, StatusCode: http.StatusInternalServerError}
	_, err = s.Application.OSOSubscriptionService().LoadOSOSubscriptionStatus(testtoken.ContextWithTokenManager(), oauth2.Token{AccessToken: accessToken})
	require.Error(s.T(), err)
	assert.IsType(s.T(), autherrors.InternalError{}, err)

	// Should return "signup_needed" if the client returns 404
	s.client.Response = &http.Response{Body: body, StatusCode: http.StatusNotFound}
	loader := testsupport.NewDummyRemoteSubscriptionLoader(&dummyConfig{s.Configuration}, s.client)
	test.ActivateDummySubscriptionLoaderFactory(s, loader)
	status, err := s.Application.OSOSubscriptionService().LoadOSOSubscriptionStatus(testtoken.ContextWithTokenManager(), oauth2.Token{AccessToken: accessToken})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "signup_needed", status)

	// Should return an error if the client returns invalid payload
	body = ioutil.NopCloser(bytes.NewReader([]byte("foo")))
	s.client.Response = &http.Response{Body: body, StatusCode: http.StatusOK}
	loader = testsupport.NewDummyRemoteSubscriptionLoader(&dummyConfig{s.Configuration}, s.client)
	test.ActivateDummySubscriptionLoaderFactory(s, loader)
	_, err = s.Application.OSOSubscriptionService().LoadOSOSubscriptionStatus(testtoken.ContextWithTokenManager(), oauth2.Token{AccessToken: accessToken})
	require.Error(s.T(), err)
	assert.IsType(s.T(), autherrors.InternalError{}, err)

	// Should return "signup_needed" if no subscription found
	body = ioutil.NopCloser(bytes.NewReader([]byte("{\"subscriptions\":[{\"status\":\"some-test-status\",\"plan\":{\"service\":{\"api_url\":\"unknown_cluster\"}}}]}")))
	s.client.Response = &http.Response{Body: body, StatusCode: http.StatusOK}
	loader = testsupport.NewDummyRemoteSubscriptionLoader(&dummyConfig{s.Configuration}, s.client)
	test.ActivateDummySubscriptionLoaderFactory(s, loader)
	status, err = s.Application.OSOSubscriptionService().LoadOSOSubscriptionStatus(testtoken.ContextWithTokenManager(), oauth2.Token{AccessToken: accessToken})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "signup_needed", status)

	// Subscription found
	body = ioutil.NopCloser(bytes.NewReader([]byte("{\"subscriptions\":[{\"status\":\"some-test-status-for2\",\"plan\":{\"service\":{\"api_url\":\"https://api.starter-us-east-2a.openshift.com/\"}}}]}")))
	s.client.Response = &http.Response{Body: body, StatusCode: http.StatusOK}
	loader = testsupport.NewDummyRemoteSubscriptionLoader(&dummyConfig{s.Configuration}, s.client)
	test.ActivateDummySubscriptionLoaderFactory(s, loader)
	status, err = s.Application.OSOSubscriptionService().LoadOSOSubscriptionStatus(testtoken.ContextWithTokenManager(), oauth2.Token{AccessToken: accessToken})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "some-test-status-for2", status)

	// Multiple subscriptions
	body = ioutil.NopCloser(bytes.NewReader([]byte("{\"subscriptions\":[{\"status\":\"some-test-status\",\"plan\":{\"service\":{\"api_url\":\"unknown_cluster\"}}},{\"status\":\"some-test-status-for2\",\"plan\":{\"service\":{\"api_url\":\"https://api.starter-us-east-2a.openshift.com/\"}}},{\"status\":\"some-test-status\",\"plan\":{\"service\":{\"api_url\":\"unknown_cluster\"}}}]}")))
	s.client.Response = &http.Response{Body: body, StatusCode: http.StatusOK}
	loader = testsupport.NewDummyRemoteSubscriptionLoader(&dummyConfig{s.Configuration}, s.client)
	test.ActivateDummySubscriptionLoaderFactory(s, loader)
	status, err = s.Application.OSOSubscriptionService().LoadOSOSubscriptionStatus(testtoken.ContextWithTokenManager(), oauth2.Token{AccessToken: accessToken})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "some-test-status-for2", status)
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
