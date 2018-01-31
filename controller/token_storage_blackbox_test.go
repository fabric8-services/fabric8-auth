package controller_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	. "github.com/fabric8-services/fabric8-auth/controller"
	errs "github.com/fabric8-services/fabric8-auth/errors"
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
	identityRepository                     account.IdentityRepository
	externalTokenRepository                provider.ExternalTokenRepository
	userRepository                         account.UserRepository
	mockKeycloakExternalTokenServiceClient mockKeycloakExternalTokenServiceClient

	providerConfigFactory      link.OauthProviderFactory
	dummyProviderConfigFactory *testsupport.DummyProviderFactory
}

func TestRunTokenStorageREST(t *testing.T) {
	suite.Run(t, &TestTokenStorageREST{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (rest *TestTokenStorageREST) SetupTest() {
	rest.DBTestSuite.SetupTest()
	rest.mockKeycloakExternalTokenServiceClient = newMockKeycloakExternalTokenServiceClient()
	rest.identityRepository = account.NewIdentityRepository(rest.DB)
	rest.externalTokenRepository = provider.NewExternalTokenRepository(rest.DB)
	rest.userRepository = account.NewUserRepository(rest.DB)
	rest.providerConfigFactory = link.NewOauthProviderFactory(rest.Configuration)
	rest.dummyProviderConfigFactory = &testsupport.DummyProviderFactory{Token: uuid.NewV4().String(), Config: rest.Configuration}
}

func (rest *TestTokenStorageREST) UnSecuredController() (*goa.Service, *TokenController) {
	svc := testsupport.ServiceAsUser("Token-Service", testsupport.TestIdentity)
	loginService := newTestKeycloakOAuthProvider(rest.Application)
	return svc, &TokenController{Controller: svc.NewController("token"), Auth: loginService, Configuration: rest.Configuration}
}

func (rest *TestTokenStorageREST) SecuredControllerWithIdentity(identity account.Identity) (*goa.Service, *TokenController) {
	loginService := newTestKeycloakOAuthProvider(rest.Application)

	svc := testsupport.ServiceAsUser("Token-Service", identity)
	return svc, NewTokenController(svc, rest.Application, loginService, &DummyLinkService{}, rest.providerConfigFactory, loginService.TokenManager, rest.mockKeycloakExternalTokenServiceClient, rest.Configuration)
}

func (rest *TestTokenStorageREST) SecuredControllerWithIdentityAndDummyProviderFactory(identity account.Identity) (*goa.Service, *TokenController) {
	loginService := newTestKeycloakOAuthProvider(rest.Application)

	svc := testsupport.ServiceAsUser("Token-Service", identity)
	return svc, NewTokenController(svc, rest.Application, loginService, &DummyLinkService{}, rest.dummyProviderConfigFactory, loginService.TokenManager, rest.mockKeycloakExternalTokenServiceClient, rest.Configuration)
}

func (rest *TestTokenStorageREST) SecuredControllerWithServiceAccount(serviceAccount account.Identity) (*goa.Service, *TokenController) {
	loginService := newTestKeycloakOAuthProvider(rest.Application)

	svc := testsupport.ServiceAsServiceAccountUser("Token-Service", serviceAccount)
	return svc, NewTokenController(svc, rest.Application, loginService, &DummyLinkService{}, rest.providerConfigFactory, loginService.TokenManager, rest.mockKeycloakExternalTokenServiceClient, rest.Configuration)
}

func (rest *TestTokenStorageREST) TestRetrieveOSOServiceAccountTokenOK() {
	rest.checkRetrieveOSOServiceAccountToken("fabric8-oso-proxy")
	rest.checkRetrieveOSOServiceAccountToken("fabric8-tenant")
}

func (rest *TestTokenStorageREST) checkRetrieveOSOServiceAccountToken(saName string) {
	sa := account.Identity{
		Username: saName,
	}
	rest.mockKeycloakExternalTokenServiceClient.scenario = "unlinked"
	service, controller := rest.SecuredControllerWithServiceAccount(sa)
	require.True(rest.T(), len(rest.Configuration.GetOSOClusters()) > 0)
	for _, cluster := range rest.Configuration.GetOSOClusters() {
		_, tokenResponse := test.RetrieveTokenOK(rest.T(), service.Context, service, controller, cluster.APIURL, nil)

		assert.Equal(rest.T(), cluster.ServiceAccountToken, tokenResponse.AccessToken)
		assert.Equal(rest.T(), "<unknown>", tokenResponse.Scope)
		assert.Equal(rest.T(), "bearer", tokenResponse.TokenType)
		require.NotNil(rest.T(), tokenResponse.Username)
		assert.Equal(rest.T(), "dsaas", *tokenResponse.Username)
	}
}

func (rest *TestTokenStorageREST) TestRetrieveOSOServiceAccountTokenForUnknownSAFails() {
	sa := account.Identity{
		Username: "unknown-sa",
	}
	rest.mockKeycloakExternalTokenServiceClient.scenario = "unlinked"
	service, controller := rest.SecuredControllerWithServiceAccount(sa)
	require.True(rest.T(), len(rest.Configuration.GetOSOClusters()) > 0)
	for _, cluster := range rest.Configuration.GetOSOClusters() {
		test.RetrieveTokenUnauthorized(rest.T(), service.Context, service, controller, cluster.APIURL, nil)
	}
}

// Not present in DB but present in Keycloak
func (rest *TestTokenStorageREST) TestRetrieveExternalTokenGithubOK() {
	identity, err := testsupport.CreateTestIdentity(rest.DB, uuid.NewV4().String(), "KC")
	require.Nil(rest.T(), err)
	rest.mockKeycloakExternalTokenServiceClient.scenario = "positive"
	service, controller := rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)
	_, tokenResponse := test.RetrieveTokenOK(rest.T(), service.Context, service, controller, "https://github.com/a/b", nil)

	expectedToken := positiveKCResponseGithub()
	rest.assertKeycloakTokenResponse(expectedToken, tokenResponse)
}

func (rest *TestTokenStorageREST) assertKeycloakTokenResponse(expected *keycloak.KeycloakExternalTokenResponse, actual *app.ExternalToken) {
	require.Equal(rest.T(), expected.AccessToken, actual.AccessToken)
	require.Equal(rest.T(), expected.Scope, actual.Scope)
	require.Equal(rest.T(), expected.TokenType, actual.TokenType)
	require.Equal(rest.T(), expected.AccessToken+"testuser", *actual.Username)
}

// Not present in DB but present in Keycloak
func (rest *TestTokenStorageREST) TestRetrieveExternalTokenOSOOK() {
	identity, err := testsupport.CreateTestIdentity(rest.DB, uuid.NewV4().String(), "KC")
	require.Nil(rest.T(), err)
	rest.mockKeycloakExternalTokenServiceClient.scenario = "positive"
	service, controller := rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)
	_, tokenResponse := test.RetrieveTokenOK(rest.T(), service.Context, service, controller, "https://api.starter-us-east-2.openshift.com", nil)

	expectedToken := positiveKCResponseOpenShift()
	rest.assertKeycloakTokenResponse(expectedToken, tokenResponse)
}

// Not present in DB and failed in Keycloak for any reason
func (rest *TestTokenStorageREST) TestRetrieveExternalTokenUnauthorized() {
	rest.checkRetrieveExternalTokenUnauthorized("https://github.com/sbose78", "github", "unlinked")
	rest.checkRetrieveExternalTokenUnauthorized("https://api.starter-us-east-2.openshift.com", "openshift-v3", "internalError")
	rest.checkRetrieveExternalTokenUnauthorized("https://github.com/sbose78", "github", "unlinked")
	rest.checkRetrieveExternalTokenUnauthorized("https://api.starter-us-east-2.openshift.com", "openshift-v3", "internalError")
}

func (rest *TestTokenStorageREST) checkRetrieveExternalTokenUnauthorized(for_ string, providerName string, kcScenario string) {
	identity, err := testsupport.CreateTestIdentity(rest.DB, uuid.NewV4().String(), "KC")
	require.Nil(rest.T(), err)
	rest.mockKeycloakExternalTokenServiceClient.scenario = kcScenario

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

	// GitHub
	prms := url.Values{
		"for": {for_},
	}

	goaCtx := goa.NewContext(service.Context, rw, req, prms)
	tokenCtx, err := app.NewRetrieveTokenContext(goaCtx, req, goa.New("TokenService"))
	require.Nil(rest.T(), err)

	err = controller.Retrieve(tokenCtx)
	require.NotNil(rest.T(), err)
	expectedHeaderValue := fmt.Sprintf("LINK url=https://auth.localhost.io/api/token/link?for=%s, description=\"%s token is missing. Link %s account\"", for_, providerName, providerName)
	assert.Contains(rest.T(), rw.Header().Get("WWW-Authenticate"), expectedHeaderValue)
	assert.Contains(rest.T(), rw.Header().Get("Access-Control-Expose-Headers"), "WWW-Authenticate")
}

// Identity does not exist.
func (rest *TestTokenStorageREST) TestRetrieveExternalTokenIdentityNotPresent() {
	identity := testsupport.TestIdentity // using an Identity which does not exist in the database.
	rest.mockKeycloakExternalTokenServiceClient.scenario = "positive"
	service, controller := rest.SecuredControllerWithIdentity(identity)
	test.RetrieveTokenUnauthorized(rest.T(), service.Context, service, controller, "https://github.com/a/b", nil)
}

// Not present in Keycloak but present in DB.
func (rest *TestTokenStorageREST) TestRetrieveExternalTokenPresentInDB() {
	rest.retrieveExternalTokenFailingInKeycloak("unlinked")
}

// Get token from keycloak fails for any reason but token present in DB.
func (rest *TestTokenStorageREST) TestRetrieveExternalTokenFailedInKeycloak() {
	rest.retrieveExternalTokenFailingInKeycloak("internalError")
}

func (rest *TestTokenStorageREST) retrieveExternalTokenFailingInKeycloak(scenario string) {
	rest.retrieveExternalTokenFromDBSuccess(scenario)
}

func (rest *TestTokenStorageREST) retrieveExternalTokenFromDBSuccess(scenario string) (account.Identity, provider.ExternalToken) {
	identity, err := testsupport.CreateTestIdentity(rest.DB, uuid.NewV4().String(), "KC")
	require.Nil(rest.T(), err)

	rest.mockKeycloakExternalTokenServiceClient.scenario = scenario
	service, controller := rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)

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
		Username:   "1234-from-dbtestuser",
	}
	rest.externalTokenRepository.Create(context.Background(), &expectedToken)

	// This call should end up in a failed KC response but a positive retrieval from the database.
	_, tokenResponse := test.RetrieveTokenOK(rest.T(), service.Context, service, controller, "https://github.com/a/b", nil)
	require.Equal(rest.T(), expectedToken.Token, tokenResponse.AccessToken)
	require.Equal(rest.T(), expectedToken.Scope, tokenResponse.Scope)
	require.Equal(rest.T(), expectedToken.Username, *tokenResponse.Username)
	require.Equal(rest.T(), "bearer", tokenResponse.TokenType)

	return identity, expectedToken
}

func (rest *TestTokenStorageREST) TestRetrieveExternalTokenBadRequest() {
	identity := testsupport.TestIdentity
	service, controller := rest.SecuredControllerWithIdentity(identity)
	test.RetrieveTokenBadRequest(rest.T(), service.Context, service, controller, "", nil)
}

// This test demonstrates that the token retrieval works successfully without the ForcePull option
// However, when the ForcePull option is passed, we determine that the token is invalid.

func (rest *TestTokenStorageREST) TestRetrieveExternalTokenInvalidOnForcePullInternalError() {

	identity, _ := rest.retrieveExternalTokenFromDBSuccess("linked")
	// Token retrieved from database is successful, but when tested with github it's invalid.
	forcePull := true
	forProvider := "https://github.com/a/b"
	rest.dummyProviderConfigFactory.LoadProfileFail = true
	service, controller := rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)
	rw, _ := test.RetrieveTokenUnauthorized(rest.T(), service.Context, service, controller, forProvider, &forcePull)
	assert.Equal(rest.T(), rw.Header().Get("WWW-Authenticate"), "LINK url=http:///api/token/link?for=https://github.com/a/b, description=\"github token is not valid or expired. Relink github account\"")
	assert.Contains(rest.T(), rw.Header().Get("Access-Control-Expose-Headers"), "WWW-Authenticate")
	rest.dummyProviderConfigFactory.LoadProfileFail = false // reset to default
}

// This test demonstrates that the token retrieval works successfully without the ForcePull option
// When the ForcePull option is passed, we determine that the token is valid.

func (rest *TestTokenStorageREST) TestRetrieveExternalTokenValidOnForcePullInternalError() {

	identity, err := testsupport.CreateTestIdentity(rest.DB, uuid.NewV4().String(), "KC")
	require.Nil(rest.T(), err)

	rest.mockKeycloakExternalTokenServiceClient.scenario = "linked"
	service, controller := rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)

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
		Username:   "1234-from-dbtestuser",
	}
	rest.externalTokenRepository.Create(context.Background(), &expectedToken)

	test.RetrieveTokenOK(rest.T(), service.Context, service, controller, "https://github.com/a/b", nil)

	// Token retrieved from database is successful, but when tested with github it's invalid.
	forcePull := true
	forProvider := "https://github.com/a/b"
	rest.dummyProviderConfigFactory.LoadProfileFail = false
	service, controller = rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)
	test.RetrieveTokenOK(rest.T(), service.Context, service, controller, forProvider, &forcePull)

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
	rest.deleteExternalToken(forResource, 1, "internalError")
	rest.deleteExternalToken(forResource, 3, "unlinked")
	rest.deleteExternalToken(forResource, 3, "positive")
	rest.deleteExternalToken(forResource, 3, "internalError")
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
	tokens, err := rest.Application.ExternalTokens().LoadByProviderIDAndIdentityID(service.Context, providerConfig.ID(), identity.ID)
	require.Nil(rest.T(), err)
	require.Equal(rest.T(), numberOfTokens, len(tokens))

	test.DeleteTokenOK(rest.T(), service.Context, service, controller, forResource)
	tokens, err = rest.Application.ExternalTokens().LoadByProviderIDAndIdentityID(service.Context, providerConfig.ID(), identity.ID)
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
	if client.scenario == "internalError" {
		return nil, errs.NewInternalError(ctx, errors.New("Internal Server Error"))
	}
	return nil, errs.NewUnauthorizedError("user not linked")
}

func (client mockKeycloakExternalTokenServiceClient) Delete(ctx context.Context, keycloakExternalTokenURL string) error {
	if client.scenario == "positive" {
		return nil
	}
	if client.scenario == "internalError" {
		return errs.NewInternalError(ctx, errors.New("Internal Server Error"))
	}
	return errs.NewUnauthorizedError("user not linked")
}

func positiveKCResponseGithub() *keycloak.KeycloakExternalTokenResponse {
	return &keycloak.KeycloakExternalTokenResponse{
		AccessToken: "1234-github",
		Scope:       "testscope",
		TokenType:   "bearer",
	}
}

func positiveKCResponseOpenShift() *keycloak.KeycloakExternalTokenResponse {
	return &keycloak.KeycloakExternalTokenResponse{
		AccessToken: "1234-openshift",
		Scope:       "testscope",
		TokenType:   "bearer",
	}
}
