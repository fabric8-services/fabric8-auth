package controller_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/configuration"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormsupport/cleaner"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	"github.com/fabric8-services/fabric8-auth/token/keycloak"
	"github.com/fabric8-services/fabric8-auth/token/link"
	"github.com/fabric8-services/fabric8-auth/token/provider"

	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestTokenStorageREST struct {
	gormtestsupport.DBTestSuite
	db                                     *gormapplication.GormDB
	identityRepository                     account.IdentityRepository
	externalTokenRepository                provider.ExternalTokenRepository
	userRepository                         account.UserRepository
	mockKeycloakExternalTokenServiceClient mockKeycloakExternalTokenServiceClient

	providerConfigFactory link.OauthProviderFactory
	clean                 func()
}

func TestRunTokenStorageREST(t *testing.T) {
	suite.Run(t, &TestTokenStorageREST{DBTestSuite: gormtestsupport.NewDBTestSuite("../config.yaml")})
}

func (rest *TestTokenStorageREST) SetupTest() {
	rest.DBTestSuite.SetupSuite()
	rest.mockKeycloakExternalTokenServiceClient = newMockKeycloakExternalTokenServiceClient()
	rest.db = gormapplication.NewGormDB(rest.DB)
	rest.identityRepository = account.NewIdentityRepository(rest.DB)
	rest.externalTokenRepository = provider.NewExternalTokenRepository(rest.DB)
	rest.userRepository = account.NewUserRepository(rest.DB)

	rest.clean = cleaner.DeleteCreatedEntities(rest.DB)
	config, err := configuration.GetConfigurationData()
	if err != nil {
		panic(fmt.Errorf("Failed to setup the configuration: %s", err.Error()))
	}
	rest.Configuration = config
	rest.providerConfigFactory = link.NewOauthProviderFactory(config)
}

func (rest *TestTokenStorageREST) TearDownTest() {
	rest.clean()
}

func (rest *TestTokenStorageREST) UnSecuredController() (*goa.Service, *TokenController) {
	svc := testsupport.ServiceAsUser("Token-Service", testsupport.TestIdentity)
	return svc, &TokenController{Controller: svc.NewController("token"), Auth: TestLoginService{}, Configuration: rest.Configuration}
}

func (rest *TestTokenStorageREST) SecuredControllerWithIdentity(identity account.Identity) (*goa.Service, *TokenController) {
	loginService := newTestKeycloakOAuthProvider(rest.db, rest.Configuration)

	svc := testsupport.ServiceAsUser("Token-Service", identity)
	return svc, NewTokenController(svc, rest.db, loginService, &DummyLinkService{}, rest.providerConfigFactory, loginService.TokenManager, rest.mockKeycloakExternalTokenServiceClient, rest.Configuration)
}

// Not present in DB but present in keycloak
func (rest *TestTokenStorageREST) TestRetrieveExternalTokenGithubOK() {
	identity, err := testsupport.CreateTestIdentity(rest.DB, uuid.NewV4().String(), "KC")
	require.Nil(rest.T(), err)
	rest.mockKeycloakExternalTokenServiceClient.scenario = "positive"
	service, controller := rest.SecuredControllerWithIdentity(identity)
	_, tokenResponse := test.RetrieveTokenOK(rest.T(), service.Context, service, controller, "https://github.com/a/b")
	expectedToken := positiveKCResponseGithub()
	require.Equal(rest.T(), expectedToken.AccessToken, tokenResponse.AccessToken)
	require.Equal(rest.T(), expectedToken.Scope, tokenResponse.Scope)
	require.Equal(rest.T(), expectedToken.TokenType, tokenResponse.TokenType)
}

// Not present in DB but present in keycloak
func (rest *TestTokenStorageREST) TestRetrieveExternalTokenOSOOK() {
	identity, err := testsupport.CreateTestIdentity(rest.DB, uuid.NewV4().String(), "KC")
	require.Nil(rest.T(), err)
	rest.mockKeycloakExternalTokenServiceClient.scenario = "positive"
	service, controller := rest.SecuredControllerWithIdentity(identity)
	_, tokenResponse := test.RetrieveTokenOK(rest.T(), service.Context, service, controller, "https://api.starter-us-east-2.openshift.com")

	expectedToken := positiveKCResponseOpenShift()
	require.Equal(rest.T(), expectedToken.AccessToken, tokenResponse.AccessToken)
	require.Equal(rest.T(), expectedToken.Scope, tokenResponse.Scope)
	require.Equal(rest.T(), expectedToken.TokenType, tokenResponse.TokenType)
}

// Not present in keycloak and not present in DB
func (rest *TestTokenStorageREST) TestRetrieveExternalTokenUnauthorized() {
	identity, err := testsupport.CreateTestIdentity(rest.DB, uuid.NewV4().String(), "KC")
	require.Nil(rest.T(), err)
	rest.mockKeycloakExternalTokenServiceClient.scenario = "unlinked"

	service, controller := rest.SecuredControllerWithIdentity(identity)

	rw := httptest.NewRecorder()
	u := &url.URL{
		Scheme: "https",
		Host:   "auth.localhost.io",
		Path:   fmt.Sprintf("/api/token"),
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		panic("invalid test " + err.Error()) // bug
	}

	referrerClientURL := "https://localhost.example.ui/home"
	req.Header.Add("referer", referrerClientURL)

	prms := url.Values{
		"for": {"https://github.com/sbose78"},
	}

	goaCtx := goa.NewContext(service.Context, rw, req, prms)
	tokenCtx, err := app.NewRetrieveTokenContext(goaCtx, req, goa.New("TokenService"))
	require.Nil(rest.T(), err)

	err = controller.Retrieve(tokenCtx)
	require.NotNil(rest.T(), err)
	expectedHeaderValue := "LINK url=https://auth.localhost.io/api/token/link, description=\"github token is missing. Link github account\""
	assert.Contains(rest.T(), rw.Header().Get("WWW-Authenticate"), expectedHeaderValue)
}

// Not present in keycloak and identity is not the system.
func (rest *TestTokenStorageREST) TestRetrieveExternalTokenIdentityNotPresent() {
	identity := testsupport.TestIdentity // using an Identity which has no existence the database.
	rest.mockKeycloakExternalTokenServiceClient.scenario = "unlinked"
	service, controller := rest.SecuredControllerWithIdentity(identity)
	test.RetrieveTokenUnauthorized(rest.T(), service.Context, service, controller, "https://github.com/a/b")
}

// Not present in keycloak but present in DB.
func (rest *TestTokenStorageREST) TestRetrieveExternalTokenPresentInDB() {
	identity, err := testsupport.CreateTestIdentity(rest.DB, uuid.NewV4().String(), "KC")
	require.Nil(rest.T(), err)

	rest.mockKeycloakExternalTokenServiceClient.scenario = "unlinked"
	service, controller := rest.SecuredControllerWithIdentity(identity)

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}
	providerConfig, err := rest.providerConfigFactory.NewOauthProvider(context.Background(), r, "https://github.com/a/b")
	require.Nil(rest.T(), err)

	expectedToken := provider.ExternalToken{
		ProviderID: providerConfig.ID(),
		Scope:      providerConfig.Scopes(),
		IdentityID: identity.ID,
		Token:      "1234-from-db",
	}
	rest.externalTokenRepository.Create(context.Background(), &expectedToken)

	// This call should end up in a failed KC response , but a positive retrieval from the database.
	_, tokenResponse := test.RetrieveTokenOK(rest.T(), service.Context, service, controller, "https://github.com/a/b")
	require.Equal(rest.T(), expectedToken.Token, tokenResponse.AccessToken)
	require.Equal(rest.T(), expectedToken.Scope, tokenResponse.Scope)
	require.Equal(rest.T(), "bearer", tokenResponse.TokenType)
}

func (rest *TestTokenStorageREST) TestRetrieveExternalTokenBadRequest() {
	identity := testsupport.TestIdentity
	service, controller := rest.SecuredControllerWithIdentity(identity)
	test.RetrieveTokenBadRequest(rest.T(), service.Context, service, controller, "")
}

func (rest *TestTokenStorageREST) TestDeleteExternalTokenBadRequest() {
	identity := testsupport.TestIdentity
	service, controller := rest.SecuredControllerWithIdentity(identity)
	test.DeleteTokenBadRequest(rest.T(), service.Context, service, controller, "")
}

func (rest *TestTokenStorageREST) TestDeleteExternalTokenIdentityNotPresent() {
	identity := testsupport.TestIdentity // using an Identity which has no existence the database.
	rest.mockKeycloakExternalTokenServiceClient.scenario = "unlinked"
	service, controller := rest.SecuredControllerWithIdentity(identity)
	test.DeleteTokenUnauthorized(rest.T(), service.Context, service, controller, "https://github.com/a/b")
}

func (rest *TestTokenStorageREST) TestDeleteExternalTokenGithubOK() {
	rest.deleteExternalTokenOK("https://github.com/a/b")
}

func (rest *TestTokenStorageREST) TestDeleteExternalTokenOSOOK() {
	rest.deleteExternalTokenOK("https://api.starter-us-east-2.openshift.com")
}

func (rest *TestTokenStorageREST) deleteExternalTokenOK(forResource string) {
	rest.deleteExternalToken(forResource, 1, "unlinked")
	rest.deleteExternalToken(forResource, 1, "positive")
	rest.deleteExternalToken(forResource, 3, "unlinked")
	rest.deleteExternalToken(forResource, 3, "positive")
}

func (rest *TestTokenStorageREST) deleteExternalToken(forResource string, numberOfTokens int, scenario string) {
	identity, err := testsupport.CreateTestIdentity(rest.DB, uuid.NewV4().String(), "KC")
	require.Nil(rest.T(), err)
	rest.mockKeycloakExternalTokenServiceClient.scenario = scenario
	service, controller := rest.SecuredControllerWithIdentity(identity)
	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}
	providerConfig, err := rest.providerConfigFactory.NewOauthProvider(context.Background(), r, forResource)
	require.Nil(rest.T(), err)

	// OK is returned even if there is nothing to delete
	test.DeleteTokenOK(rest.T(), service.Context, service, controller, forResource)

	for i := 0; i < numberOfTokens; i++ {
		expectedToken := provider.ExternalToken{
			ProviderID: providerConfig.ID(),
			Scope:      providerConfig.Scopes(),
			IdentityID: identity.ID,
			Token:      "1234-from-db",
		}
		err = rest.externalTokenRepository.Create(context.Background(), &expectedToken)
		require.Nil(rest.T(), err)
	}
	tokens, err := rest.db.ExternalTokens().LoadByProviderIDAndIdentityID(service.Context, providerConfig.ID(), identity.ID)
	require.Nil(rest.T(), err)
	require.Equal(rest.T(), numberOfTokens, len(tokens))

	test.DeleteTokenOK(rest.T(), service.Context, service, controller, forResource)
	tokens, err = rest.db.ExternalTokens().LoadByProviderIDAndIdentityID(service.Context, providerConfig.ID(), identity.ID)
	require.Nil(rest.T(), err)
	require.Empty(rest.T(), tokens)
}

type mockKeycloakExternalTokenServiceClient struct {
	scenario string
}

func newMockKeycloakExternalTokenServiceClient() mockKeycloakExternalTokenServiceClient {
	return mockKeycloakExternalTokenServiceClient{
		scenario: "positive",
	}
}

func (client mockKeycloakExternalTokenServiceClient) Get(ctx context.Context, accessToken string, keycloakExternalTokenURL string) (*keycloak.KeycloakExternalTokenResponse, error) {
	if client.scenario == "positive" && strings.Contains(keycloakExternalTokenURL, "github") {
		return positiveKCResponseGithub(), nil
	} else if client.scenario == "positive" {
		return positiveKCResponseOpenShift(), nil
	}
	return nil, errors.NewUnauthorizedError("user not linked")
}

func (client mockKeycloakExternalTokenServiceClient) Delete(ctx context.Context, keycloakExternalTokenURL string) error {
	if client.scenario == "positive" {
		return nil
	}
	return errors.NewUnauthorizedError("user not linked")
}

func positiveKCResponseGithub() *keycloak.KeycloakExternalTokenResponse {
	return &keycloak.KeycloakExternalTokenResponse{
		AccessToken: "1234-github",
		Scope:       "default-github",
		TokenType:   "bearer",
	}
}

func positiveKCResponseOpenShift() *keycloak.KeycloakExternalTokenResponse {
	return &keycloak.KeycloakExternalTokenResponse{
		AccessToken: "1234-openshift",
		Scope:       "default-openshift",
		TokenType:   "bearer",
	}
}
