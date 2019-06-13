package service_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"golang.org/x/oauth2"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/factory"
	subscription "github.com/fabric8-services/fabric8-auth/authentication/subscription/service"
	autherrors "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/test"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testsubscription "github.com/fabric8-services/fabric8-auth/test/generated/authentication/subscription/service"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"

	jwt "github.com/dgrijalva/jwt-go"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	gock "gopkg.in/h2non/gock.v1"
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

func (s *osoSubscriptionServiceTestSuite) TestLoadOSOSubscriptionStatus() {
	// given
	appRegURL := "https://some.osourl.io"
	admin := "test-admin"
	config := testsubscription.NewOSOSubscriptionServiceConfigurationMock(s.T())
	config.GetOSORegistrationAppURLFunc = func() string {
		return appRegURL
	}
	config.GetOSORegistrationAppAdminUsernameFunc = func() string {
		return admin
	}
	config.GetOSORegistrationAppAdminTokenFunc = func() string {
		return fmt.Sprintf("%s-token", admin)
	}
	clusterServiceMock := testsupport.NewClusterServiceMock(s.T())
	svcCtx := factory.NewServiceContext(s.Application, s.Application, nil, nil, factory.WithClusterService(clusterServiceMock))
	svc := subscription.NewOSOSubscriptionService(svcCtx, config)

	var username, accessToken string
	s.SetupSubtest = func() {
		username = uuid.NewV4().String()
		var err error
		accessToken, err = testtoken.GenerateToken(uuid.NewV4().String(), username)
		require.NoError(s.T(), err)
	}
	defer gock.Off()
	gock.Observe(gock.DumpRequest)

	s.Run("success", func() {

		s.Run("subscription found", func() {
			// intercept call to remote Online Reg App Service
			gock.New(config.GetOSORegistrationAppURL()).
				Get(fmt.Sprintf("api/accounts/%s/subscriptions", username)).
				MatchParam("authorization_username", config.GetOSORegistrationAppAdminUsername()).
				MatchHeader("Authorization", fmt.Sprintf("Bearer %s", config.GetOSORegistrationAppAdminToken())).
				Reply(200).BodyString(`{
				"subscriptions":[
					{
						"status":"some-test-status",
						"plan":{
							"service":{
								"api_url":"https://api.starter-us-east-2a.openshift.com"
							}
						}
					}
				]
			}`)
			// when
			status, err := svc.LoadOSOSubscriptionStatus(testtoken.ContextWithTokenManager(), oauth2.Token{AccessToken: accessToken})
			// then
			require.NoError(s.T(), err)
			assert.Equal(s.T(), "some-test-status", status)
		})

		s.Run("multiple subscriptions", func() {
			// intercept call to remote Online Reg App Service
			gock.New(config.GetOSORegistrationAppURL()).
				Get(fmt.Sprintf("api/accounts/%s/subscriptions", username)).
				MatchParam("authorization_username", config.GetOSORegistrationAppAdminUsername()).
				MatchHeader("Authorization", fmt.Sprintf("Bearer %s", config.GetOSORegistrationAppAdminToken())).
				Reply(200).BodyString(`{
				"subscriptions":[
					{
						"status":"some-test-status",
						"plan":{
							"service":{
								"api_url":"unknown_cluster"
							}
						}
					},
					{
						"status":"some-test-status",
						"plan":{
							"service":{
								"api_url":"https://api.starter-us-east-2a.openshift.com"
							}
						}
					},
					{
						"status":"some-test-status",
						"plan":{
							"service":{
								"api_url":"other_unknown_cluster"
							}
						}
					}
				]
			}`)
			// when
			status, err := svc.LoadOSOSubscriptionStatus(testtoken.ContextWithTokenManager(), oauth2.Token{AccessToken: accessToken})
			// then
			require.NoError(s.T(), err)
			assert.Equal(s.T(), "some-test-status", status)
		})
	})

	s.Run("failure", func() {

		s.Run("should return an error if token is invalid", func() {
			// intercept call to remote Online Reg App Service
			gock.New(config.GetOSORegistrationAppURL()).
				Get(fmt.Sprintf("api/accounts/%s/subscriptions", username)).
				MatchParam("authorization_username", config.GetOSORegistrationAppAdminUsername()).
				MatchHeader("Authorization", fmt.Sprintf("Bearer %s", config.GetOSORegistrationAppAdminToken())).
				Reply(500)
			// when
			_, err := svc.LoadOSOSubscriptionStatus(testtoken.ContextWithTokenManager(), oauth2.Token{})
			// then
			require.Error(s.T(), err)
			assert.IsType(s.T(), &jwt.ValidationError{}, err)
		})

		s.Run("should return an error if token manager is missing", func() {
			// intercept call to remote Online Reg App Service
			gock.New(config.GetOSORegistrationAppURL()).
				Get(fmt.Sprintf("api/accounts/%s/subscriptions", username)).
				MatchParam("authorization_username", config.GetOSORegistrationAppAdminUsername()).
				MatchHeader("Authorization", fmt.Sprintf("Bearer %s", config.GetOSORegistrationAppAdminToken())).
				Reply(500)
			// when
			_, err := svc.LoadOSOSubscriptionStatus(context.Background(), oauth2.Token{AccessToken: accessToken})
			// then
			require.Error(s.T(), err)
			assert.IsType(s.T(), autherrors.InternalError{}, err)
		})

		s.Run("should return an error if the client failed", func() {
			// intercept call to remote Online Reg App Service
			gock.New(config.GetOSORegistrationAppURL()).
				Get(fmt.Sprintf("api/accounts/%s/subscriptions", username)).
				MatchParam("authorization_username", config.GetOSORegistrationAppAdminUsername()).
				MatchHeader("Authorization", fmt.Sprintf("Bearer %s", config.GetOSORegistrationAppAdminToken())).
				Reply(500)
			// when
			_, err := svc.LoadOSOSubscriptionStatus(testtoken.ContextWithTokenManager(), oauth2.Token{AccessToken: accessToken})
			// then
			require.Error(s.T(), err)
			assert.IsType(s.T(), autherrors.InternalError{}, err)
		})

		s.Run("should return an error if the client returns any status but 200 or 404", func() {
			// intercept call to remote Online Reg App Service
			gock.New(config.GetOSORegistrationAppURL()).
				Get(fmt.Sprintf("api/accounts/%s/subscriptions", username)).
				MatchParam("authorization_username", config.GetOSORegistrationAppAdminUsername()).
				MatchHeader("Authorization", fmt.Sprintf("Bearer %s", config.GetOSORegistrationAppAdminToken())).
				Reply(501)
			// when
			_, err := svc.LoadOSOSubscriptionStatus(testtoken.ContextWithTokenManager(), oauth2.Token{AccessToken: accessToken})
			// then
			require.Error(s.T(), err)
			assert.IsType(s.T(), autherrors.InternalError{}, err)
		})

		s.Run("should return signup_needed if the client returns 404", func() {
			// intercept call to remote Online Reg App Service
			gock.New(config.GetOSORegistrationAppURL()).
				Get(fmt.Sprintf("api/accounts/%s/subscriptions", username)).
				MatchParam("authorization_username", config.GetOSORegistrationAppAdminUsername()).
				MatchHeader("Authorization", fmt.Sprintf("Bearer %s", config.GetOSORegistrationAppAdminToken())).
				Reply(404)
			// when
			status, err := svc.LoadOSOSubscriptionStatus(testtoken.ContextWithTokenManager(), oauth2.Token{AccessToken: accessToken})
			// then
			require.NoError(s.T(), err)
			assert.Equal(s.T(), "signup_needed", status)
		})

		s.Run("should return an error if the client returns invalid payload", func() {
			// intercept call to remote Online Reg App Service
			gock.New(config.GetOSORegistrationAppURL()).
				Get(fmt.Sprintf("api/accounts/%s/subscriptions", username)).
				MatchParam("authorization_username", config.GetOSORegistrationAppAdminUsername()).
				MatchHeader("Authorization", fmt.Sprintf("Bearer %s", config.GetOSORegistrationAppAdminToken())).
				Reply(200).BodyString("foo")
			// when
			_, err := svc.LoadOSOSubscriptionStatus(testtoken.ContextWithTokenManager(), oauth2.Token{AccessToken: accessToken})
			// then
			require.Error(s.T(), err)
			assert.IsType(s.T(), autherrors.InternalError{}, err)
		})

		s.Run("should return 'signup_needed' if no subscription found", func() {
			// intercept call to remote Online Reg App Service
			gock.New(config.GetOSORegistrationAppURL()).
				Get(fmt.Sprintf("api/accounts/%s/subscriptions", username)).
				MatchParam("authorization_username", config.GetOSORegistrationAppAdminUsername()).
				MatchHeader("Authorization", fmt.Sprintf("Bearer %s", config.GetOSORegistrationAppAdminToken())).
				Reply(200).BodyString(`{
				"subscriptions":[
					{
						"status":"some-test-status",
						"plan":{
							"service":{
								"api_url":"unknown_cluster"
							}
						}
					}
				]
			}`)
			// when
			status, err := svc.LoadOSOSubscriptionStatus(testtoken.ContextWithTokenManager(), oauth2.Token{AccessToken: accessToken})
			// then
			require.NoError(s.T(), err)
			assert.Equal(s.T(), "signup_needed", status)
		})
	})

}

func (s *osoSubscriptionServiceTestSuite) TestDeactivateUser() {
	// given
	appRegURL := "https://some.osourl.io"
	admin := "test-admin"
	svcCtx := factory.NewServiceContext(s.Application, s.Application, nil, nil)
	config := testsubscription.NewOSOSubscriptionServiceConfigurationMock(s.T())
	config.GetOSORegistrationAppURLFunc = func() string {
		return appRegURL
	}
	config.GetOSORegistrationAppAdminUsernameFunc = func() string {
		return admin
	}
	config.GetOSORegistrationAppAdminTokenFunc = func() string {
		return fmt.Sprintf("%s-token", admin)
	}
	svc := subscription.NewOSOSubscriptionService(svcCtx, config)

	defer gock.Off()
	gock.Observe(gock.DumpRequest)

	s.Run("success", func() {
		s.Run("ok", func() {
			username := fmt.Sprintf("user-%s", uuid.NewV4())
			gock.New(config.GetOSORegistrationAppURL()).
				Post(fmt.Sprintf("api/accounts/%s/deprovision_osio", username)).
				MatchParam("authorization_username", config.GetOSORegistrationAppAdminUsername()).
				MatchHeader("Authorization", fmt.Sprintf("Bearer %s", config.GetOSORegistrationAppAdminToken())).
				Reply(200)
			// when
			err := svc.DeactivateUser(context.Background(), username)
			// then
			require.NoError(s.T(), err)
		})
	})

	s.Run("failure", func() {
		s.Run("should return an error if the client returns 500", func() {
			username := fmt.Sprintf("user-%s", uuid.NewV4())
			gock.New(config.GetOSORegistrationAppURL()).
				Get(fmt.Sprintf("api/accounts/%s/deprovision_osio", username)).
				MatchParam("authorization_username", config.GetOSORegistrationAppAdminUsername()).
				MatchHeader("Authorization", fmt.Sprintf("Bearer %s", config.GetOSORegistrationAppAdminToken())).
				Reply(500)
			// when
			err := svc.DeactivateUser(context.Background(), username)
			// then
			require.Error(s.T(), err)
		})

		s.Run("should return an error if the client returns 404", func() {
			username := fmt.Sprintf("user-%s", uuid.NewV4())
			gock.New(config.GetOSORegistrationAppURL()).
				Post(fmt.Sprintf("api/accounts/%s/deprovision_osio", username)).
				MatchParam("authorization_username", config.GetOSORegistrationAppAdminUsername()).
				MatchHeader("Authorization", fmt.Sprintf("Bearer %s", config.GetOSORegistrationAppAdminToken())).
				Reply(404)
			// when
			err := svc.DeactivateUser(context.Background(), username)
			// then
			require.Error(s.T(), err)
		})
	})
}
