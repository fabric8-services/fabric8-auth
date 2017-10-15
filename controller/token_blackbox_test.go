package controller_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/configuration"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/resource"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"

	"github.com/goadesign/goa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestTokenREST struct {
	suite.Suite
	config *configuration.ConfigurationData
}

func TestRunTokenREST(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	suite.Run(t, &TestTokenREST{})
}

func (rest *TestTokenREST) SetupSuite() {
	var err error
	rest.config, err = configuration.GetConfigurationData()
	if err != nil {
		panic(fmt.Errorf("Failed to setup the configuration: %s", err.Error()))
	}
}

func (rest *TestTokenREST) UnSecuredController() (*goa.Service, *TokenController) {
	svc := testsupport.ServiceAsUser("Token-Service", testsupport.TestIdentity)
	return svc, &TokenController{Controller: svc.NewController("token"), Auth: TestLoginService{}, Configuration: rest.config}
}

func (rest *TestTokenREST) SecuredController() (*goa.Service, *TokenController) {
	loginService := newTestKeycloakOAuthProvider(&gormapplication.GormDB{}, rest.config)
	svc := testsupport.ServiceAsUser("Token-Service", testsupport.TestIdentity)

	linkService := &DummyLinkService{}
	return svc, NewTokenController(svc, nil, loginService, linkService, nil, loginService.TokenManager, newMockKeycloakExternalTokenServiceClient(), rest.config)
}

func (rest *TestTokenREST) TestRefreshTokenUsingNilTokenFails() {
	t := rest.T()
	service, controller := rest.SecuredController()

	payload := &app.RefreshToken{}
	_, err := test.RefreshTokenBadRequest(t, service.Context, service, controller, payload)
	assert.NotNil(t, err)
}

func (rest *TestTokenREST) TestLinkForInvalidTokenFails() {
	service, controller := rest.SecuredController()

	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.S-vR8LZTQ92iqGCR3rNUG0MiGx2N5EBVq0frCHP_bJ8"
	redirect := "https://openshift.io"
	payload := &app.LinkPayload{Token: token, For: "https://github.com/org/repo", Redirect: &redirect}
	test.LinkTokenUnauthorized(rest.T(), service.Context, service, controller, payload)
}

func (rest *TestTokenREST) TestLinkNoRedirectNoReferrerFails() {
	service, controller := rest.SecuredController()

	token, _ := testtoken.GenerateTokenWithClaims(nil)
	payload := &app.LinkPayload{Token: token, For: "https://github.com/org/repo"}
	test.LinkTokenBadRequest(rest.T(), service.Context, service, controller, payload)
}

func (rest *TestTokenREST) TestLinkRedirects() {
	service, controller := rest.SecuredController()

	token, _ := testtoken.GenerateTokenWithClaims(nil)
	redirect := "https://openshift.io"
	payload := &app.LinkPayload{Token: token, For: "https://github.com/org/repo", Redirect: &redirect}
	response := test.LinkTokenSeeOther(rest.T(), service.Context, service, controller, payload)
	require.NotNil(rest.T(), response)
	location := response.Header()["Location"]
	require.Equal(rest.T(), 1, len(location))
	require.Equal(rest.T(), "providerLocation", location[0])
}

func (rest *TestTokenREST) TestLinkCallbackRedirects() {
	service, controller := rest.SecuredController()

	response := test.CallbackTokenTemporaryRedirect(rest.T(), service.Context, service, controller, "", "")
	require.NotNil(rest.T(), response)
	location := response.Header()["Location"]
	require.Equal(rest.T(), 1, len(location))
	require.Equal(rest.T(), "originalLocation", location[0])
}

func validateToken(t *testing.T, token *app.AuthToken, controler *TokenController) {
	assert.NotNil(t, token, "Token data is nil")
	assert.NotEmpty(t, token.Token.AccessToken, "Access token is empty")
	assert.NotEmpty(t, token.Token.RefreshToken, "Refresh token is empty")
	assert.NotEmpty(t, token.Token.TokenType, "Token type is empty")
	assert.NotNil(t, token.Token.ExpiresIn, "Expires-in is nil")
	assert.NotNil(t, token.Token.RefreshExpiresIn, "Refresh-expires-in is nil")
	assert.NotNil(t, token.Token.NotBeforePolicy, "Not-before-policy is nil")
}

type DummyLinkService struct {
}

func (s *DummyLinkService) ProviderLocation(ctx context.Context, req *goa.RequestData, identityID string, forResource string, redirectURL string) (string, error) {
	return "providerLocation", nil
}

func (s *DummyLinkService) Callback(ctx context.Context, req *goa.RequestData, state string, code string) (string, error) {
	return "originalLocation", nil
}
