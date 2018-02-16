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
	rest.providerConfigFactory = link.NewOauthProviderFactory(rest.Configuration, rest.Application)
	rest.dummyProviderConfigFactory = &testsupport.DummyProviderFactory{Token: uuid.NewV4().String(), Config: rest.Configuration, DB: rest.Application}
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
		assert.Equal(rest.T(), "dsaas", tokenResponse.Username)
		assert.Equal(rest.T(), cluster.APIURL, tokenResponse.ProviderURL)
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
	rest.assertKeycloakTokenResponse("https://github.com", expectedToken, tokenResponse)

	// Alias
	_, tokenResponse = test.RetrieveTokenOK(rest.T(), service.Context, service, controller, "github", nil)
	rest.assertKeycloakTokenResponse("https://github.com", expectedToken, tokenResponse)
}

func (rest *TestTokenStorageREST) assertKeycloakTokenResponse(expectedProviderURL string, expected *keycloak.KeycloakExternalTokenResponse, actual *app.ExternalToken) {
	require.Equal(rest.T(), expected.AccessToken, actual.AccessToken)
	require.Equal(rest.T(), expected.Scope, actual.Scope)
	require.Equal(rest.T(), expected.TokenType, actual.TokenType)
	require.Equal(rest.T(), expected.AccessToken+"testuser", actual.Username)
	require.Equal(rest.T(), expectedProviderURL, actual.ProviderURL)
}

// Not present in DB but present in Keycloak
func (rest *TestTokenStorageREST) TestRetrieveExternalTokenOSOOK() {
	identity, err := testsupport.CreateTestIdentity(rest.DB, uuid.NewV4().String(), "KC")
	require.Nil(rest.T(), err)
	rest.mockKeycloakExternalTokenServiceClient.scenario = "positive"
	service, controller := rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)
	_, tokenResponse := test.RetrieveTokenOK(rest.T(), service.Context, service, controller, "https://api.starter-us-east-2.openshift.com", nil)

	expectedToken := positiveKCResponseOpenShift()
	rest.assertKeycloakTokenResponse("https://api.starter-us-east-2.openshift.com", expectedToken, tokenResponse)

	// Alias
	_, tokenResponse = test.RetrieveTokenOK(rest.T(), service.Context, service, controller, "openshift", nil)
	rest.assertKeycloakTokenResponse("https://api.starter-us-east-2.openshift.com", expectedToken, tokenResponse)

	// Another cluster
	identity, err = testsupport.CreateTestIdentityAndUserWithDefaultProviderType(rest.DB, uuid.NewV4().String())
	service, controller = rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)
	_, tokenResponse = test.RetrieveTokenOK(rest.T(), service.Context, service, controller, "openshift", nil)
	rest.assertKeycloakTokenResponse("https://api.starter-us-east-2a.openshift.com", expectedToken, tokenResponse)
}

// Not present in DB and failed in Keycloak for any reason
func (rest *TestTokenStorageREST) TestRetrieveExternalTokenUnauthorized() {
	rest.checkRetrieveExternalTokenUnauthorized("https://github.com/sbose78", "github", "unlinked")
	rest.checkRetrieveExternalTokenUnauthorized("github", "github", "unlinked")
	rest.checkRetrieveExternalTokenUnauthorized("https://api.starter-us-east-2.openshift.com", "openshift-v3", "unlinked")
	rest.checkRetrieveExternalTokenUnauthorized("openshift", "openshift-v3", "unlinked")

	rest.checkRetrieveExternalTokenUnauthorized("https://github.com/sbose78", "github", "internalError")
	rest.checkRetrieveExternalTokenUnauthorized("github", "github", "internalError")
	rest.checkRetrieveExternalTokenUnauthorized("https://api.starter-us-east-2.openshift.com", "openshift-v3", "internalError")
	rest.checkRetrieveExternalTokenUnauthorized("openshift", "openshift-v3", "internalError")
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
	// using an Identity which does not exist in the database.
	identity := account.Identity{
		ID:       uuid.NewV4(),
		Username: "TestDeveloper",
	}
	rest.mockKeycloakExternalTokenServiceClient.scenario = "positive"
	service, controller := rest.SecuredControllerWithIdentity(identity)
	test.RetrieveTokenUnauthorized(rest.T(), service.Context, service, controller, "https://github.com/a/b", nil)
	test.RetrieveTokenUnauthorized(rest.T(), service.Context, service, controller, "github", nil)
	test.RetrieveTokenUnauthorized(rest.T(), service.Context, service, controller, "https://api.starter-us-east-2.openshift.com", nil)
	test.RetrieveTokenUnauthorized(rest.T(), service.Context, service, controller, "openshift", nil)
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
	rest.retrieveExternalGitHubTokenFromDBSuccess(scenario)
	rest.retrieveExternalOSOTokenFromDBSuccess(scenario)
}

func (rest *TestTokenStorageREST) retrieveExternalGitHubTokenFromDBSuccess(scenario string) (account.Identity, provider.ExternalToken) {
	identity, err := testsupport.CreateTestIdentity(rest.DB, uuid.NewV4().String(), "KC")
	require.Nil(rest.T(), err)

	rest.mockKeycloakExternalTokenServiceClient.scenario = scenario
	service, controller := rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}
	providerConfig, err := rest.providerConfigFactory.NewOauthProvider(context.Background(), identity.ID, r, "https://github.com/a/b")
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
	require.Equal(rest.T(), expectedToken.Username, tokenResponse.Username)
	require.Equal(rest.T(), "bearer", tokenResponse.TokenType)
	require.Equal(rest.T(), "https://github.com", tokenResponse.ProviderURL)

	// Alias
	_, tokenResponse = test.RetrieveTokenOK(rest.T(), service.Context, service, controller, "github", nil)
	require.Equal(rest.T(), expectedToken.Token, tokenResponse.AccessToken)
	require.Equal(rest.T(), expectedToken.Scope, tokenResponse.Scope)
	require.Equal(rest.T(), expectedToken.Username, tokenResponse.Username)
	require.Equal(rest.T(), "bearer", tokenResponse.TokenType)
	require.Equal(rest.T(), "https://github.com", tokenResponse.ProviderURL)

	return identity, expectedToken
}

func (rest *TestTokenStorageREST) retrieveExternalOSOTokenFromDBSuccess(scenario string) (account.Identity, provider.ExternalToken) {
	identity, err := testsupport.CreateTestIdentityAndUserWithDefaultProviderType(rest.DB, uuid.NewV4().String())
	require.Nil(rest.T(), err)

	rest.mockKeycloakExternalTokenServiceClient.scenario = scenario
	service, controller := rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}
	providerConfig, err := rest.providerConfigFactory.NewOauthProvider(context.Background(), identity.ID, r, "https://api.starter-us-east-2a.openshift.com")
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
	_, tokenResponse := test.RetrieveTokenOK(rest.T(), service.Context, service, controller, "https://api.starter-us-east-2a.openshift.com", nil)
	require.Equal(rest.T(), expectedToken.Token, tokenResponse.AccessToken)
	require.Equal(rest.T(), expectedToken.Scope, tokenResponse.Scope)
	require.Equal(rest.T(), expectedToken.Username, tokenResponse.Username)
	require.Equal(rest.T(), "bearer", tokenResponse.TokenType)
	require.Equal(rest.T(), "https://api.starter-us-east-2a.openshift.com", tokenResponse.ProviderURL)

	// Alias
	_, tokenResponse = test.RetrieveTokenOK(rest.T(), service.Context, service, controller, "openshift", nil)
	require.Equal(rest.T(), expectedToken.Token, tokenResponse.AccessToken)
	require.Equal(rest.T(), expectedToken.Scope, tokenResponse.Scope)
	require.Equal(rest.T(), expectedToken.Username, tokenResponse.Username)
	require.Equal(rest.T(), "bearer", tokenResponse.TokenType)
	require.Equal(rest.T(), "https://api.starter-us-east-2a.openshift.com", tokenResponse.ProviderURL)

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
	identity, _ := rest.retrieveExternalGitHubTokenFromDBSuccess("linked")
	rest.checkRetrieveExternalTokenInvalidOnForcePullInternalError(identity, "https://github.com/a/b", "github")
	rest.checkRetrieveExternalTokenInvalidOnForcePullInternalError(identity, "github", "github")

	identity, _ = rest.retrieveExternalOSOTokenFromDBSuccess("linked")
	rest.checkRetrieveExternalTokenInvalidOnForcePullInternalError(identity, "https://api.starter-us-east-2a.openshift.com", "openshift-v3")
	rest.checkRetrieveExternalTokenInvalidOnForcePullInternalError(identity, "openshift", "openshift-v3")
}

func (rest *TestTokenStorageREST) checkRetrieveExternalTokenInvalidOnForcePullInternalError(identity account.Identity, for_, providerName string) {
	// Token status is OK, but when tested with provider it's invalid.
	forcePull := true
	rest.dummyProviderConfigFactory.LoadProfileFail = true
	service, controller := rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)
	rw, _ := test.RetrieveTokenUnauthorized(rest.T(), service.Context, service, controller, for_, &forcePull)
	assert.Equal(rest.T(), rw.Header().Get("WWW-Authenticate"), fmt.Sprintf("LINK url=http:///api/token/link?for=%s, description=\"%s token is not valid or expired. Relink %s account\"", for_, providerName, providerName))
	assert.Contains(rest.T(), rw.Header().Get("Access-Control-Expose-Headers"), "WWW-Authenticate")
}

// This test demonstrates that the token retrieval works successfully without the ForcePull option
// When the ForcePull option is passed, we determine that the token is invalid.

func (rest *TestTokenStorageREST) TestRetrieveExternalTokenValidOnForcePullInternalError() {
	identity, err := testsupport.CreateTestIdentity(rest.DB, uuid.NewV4().String(), "KC")
	require.Nil(rest.T(), err)

	rest.checkRetrieveExternalTokenValidOnForcePullInternalError(identity, "https://github.com/a/b")
	rest.checkRetrieveExternalTokenValidOnForcePullInternalError(identity, "github")
	rest.checkRetrieveExternalTokenValidOnForcePullInternalError(identity, "https://api.starter-us-east-2.openshift.com")
	rest.checkRetrieveExternalTokenValidOnForcePullInternalError(identity, "openshift")
}

func (rest *TestTokenStorageREST) checkRetrieveExternalTokenValidOnForcePullInternalError(identity account.Identity, for_ string) {
	rest.mockKeycloakExternalTokenServiceClient.scenario = "linked"
	service, controller := rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}
	providerConfig, err := rest.providerConfigFactory.NewOauthProvider(context.Background(), identity.ID, r, for_)
	require.Nil(rest.T(), err)

	expectedToken := provider.ExternalToken{
		ProviderID: providerConfig.ID(),
		Scope:      providerConfig.Scopes(),
		IdentityID: identity.ID,
		Token:      "1234-from-db",
		Username:   "1234-from-dbtestuser",
	}
	rest.externalTokenRepository.Create(context.Background(), &expectedToken)

	test.RetrieveTokenOK(rest.T(), service.Context, service, controller, for_, nil)

	// Token retrieved from database is successful and when tested with github it's valid.
	forcePull := true
	rest.dummyProviderConfigFactory.LoadProfileFail = false
	service, controller = rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)
	test.RetrieveTokenOK(rest.T(), service.Context, service, controller, for_, &forcePull)
}

// Not present in DB but present in Keycloak
func (rest *TestTokenStorageREST) TestStatusExternalTokenGithubOK() {
	identity, err := testsupport.CreateTestIdentity(rest.DB, uuid.NewV4().String(), "KC")
	require.Nil(rest.T(), err)
	rest.mockKeycloakExternalTokenServiceClient.scenario = "positive"
	service, controller := rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)

	_, tokenStatus := test.StatusTokenOK(rest.T(), service.Context, service, controller, "https://github.com/a/b", nil)
	rest.assertTokenStatusAndTokenResponse(positiveKCResponseGithub(), "https://github.com", tokenStatus)

	_, tokenStatus = test.StatusTokenOK(rest.T(), service.Context, service, controller, "github", nil)
	rest.assertTokenStatusAndTokenResponse(positiveKCResponseGithub(), "https://github.com", tokenStatus)

	_, tokenStatus = test.StatusTokenOK(rest.T(), service.Context, service, controller, "https://api.starter-us-east-2.openshift.com", nil)
	rest.assertTokenStatusAndTokenResponse(positiveKCResponseOpenShift(), "https://api.starter-us-east-2.openshift.com", tokenStatus)

	_, tokenStatus = test.StatusTokenOK(rest.T(), service.Context, service, controller, "openshift", nil)
	rest.assertTokenStatusAndTokenResponse(positiveKCResponseOpenShift(), "https://api.starter-us-east-2.openshift.com", tokenStatus)
}

func (rest *TestTokenStorageREST) assertTokenStatusAndTokenResponse(expectedTokenResponse *keycloak.KeycloakExternalTokenResponse, expectedURL string, actualStatus *app.ExternalTokenStatus) {
	require.NotNil(rest.T(), actualStatus)
	assert.Equal(rest.T(), expectedTokenResponse.AccessToken+"testuser", actualStatus.Username)
	assert.Equal(rest.T(), expectedURL, actualStatus.ProviderURL)
}

func (rest *TestTokenStorageREST) assertTokenStatus(expectedUsername, expectedURL string, actualStatus *app.ExternalTokenStatus) {
	require.NotNil(rest.T(), actualStatus)
	assert.Equal(rest.T(), expectedUsername, actualStatus.Username)
	assert.Equal(rest.T(), expectedURL, actualStatus.ProviderURL)
}

// Not present in Keycloak but present in DB.
func (rest *TestTokenStorageREST) TestStatusExternalTokenPresentInDB() {
	rest.statusExternalGitHubTokenFromDBSuccess("unlinked")
	rest.statusExternalOSOTokenFromDBSuccess("unlinked")
}

// Get token from keycloak fails for any reason but token present in DB.
func (rest *TestTokenStorageREST) TestStatusExternalTokenFailedInKeycloak() {
	rest.statusExternalGitHubTokenFromDBSuccess("internalError")
	rest.statusExternalOSOTokenFromDBSuccess("internalError")
}

func (rest *TestTokenStorageREST) statusExternalGitHubTokenFromDBSuccess(scenario string) account.Identity {
	identity, _ := rest.retrieveExternalGitHubTokenFromDBSuccess(scenario)
	service, controller := rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)

	_, tokenStatus := test.StatusTokenOK(rest.T(), service.Context, service, controller, "https://github.com/a/b", nil)
	rest.assertTokenStatus("1234-from-dbtestuser", "https://github.com", tokenStatus)

	_, tokenStatus = test.StatusTokenOK(rest.T(), service.Context, service, controller, "github", nil)
	rest.assertTokenStatus("1234-from-dbtestuser", "https://github.com", tokenStatus)

	return identity
}

func (rest *TestTokenStorageREST) statusExternalOSOTokenFromDBSuccess(scenario string) account.Identity {
	identity, _ := rest.retrieveExternalOSOTokenFromDBSuccess(scenario)
	service, controller := rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)

	_, tokenStatus := test.StatusTokenOK(rest.T(), service.Context, service, controller, "https://api.starter-us-east-2a.openshift.com", nil)
	rest.assertTokenStatus("1234-from-dbtestuser", "https://api.starter-us-east-2a.openshift.com", tokenStatus)

	_, tokenStatus = test.StatusTokenOK(rest.T(), service.Context, service, controller, "openshift", nil)
	rest.assertTokenStatus("1234-from-dbtestuser", "https://api.starter-us-east-2a.openshift.com", tokenStatus)

	return identity
}

// Not present in DB and failed in Keycloak for any reason
func (rest *TestTokenStorageREST) TestStatusExternalTokenUnauthorized() {
	rest.checkStatusExternalTokenUnauthorized("https://github.com/sbose78", "github", "unlinked")
	rest.checkStatusExternalTokenUnauthorized("github", "github", "unlinked")
	rest.checkStatusExternalTokenUnauthorized("https://api.starter-us-east-2.openshift.com", "openshift-v3", "unlinked")
	rest.checkStatusExternalTokenUnauthorized("openshift", "openshift-v3", "unlinked")

	rest.checkStatusExternalTokenUnauthorized("https://github.com/sbose78", "github", "internalError")
	rest.checkStatusExternalTokenUnauthorized("github", "github", "internalError")
	rest.checkStatusExternalTokenUnauthorized("https://api.starter-us-east-2.openshift.com", "openshift-v3", "internalError")
	rest.checkStatusExternalTokenUnauthorized("openshift", "openshift-v3", "internalError")
}

func (rest *TestTokenStorageREST) checkStatusExternalTokenUnauthorized(for_ string, providerName string, kcScenario string) {
	identity, err := testsupport.CreateTestIdentity(rest.DB, uuid.NewV4().String(), "KC")
	require.Nil(rest.T(), err)
	rest.mockKeycloakExternalTokenServiceClient.scenario = kcScenario

	service, controller := rest.SecuredControllerWithIdentity(identity)

	rw := httptest.NewRecorder()
	u := &url.URL{
		Scheme: "https",
		Host:   "auth.localhost.io",
		Path:   fmt.Sprintf("/api/token/status"),
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
	tokenCtx, err := app.NewStatusTokenContext(goaCtx, req, goa.New("TokenService"))
	require.Nil(rest.T(), err)

	err = controller.Status(tokenCtx)
	require.NotNil(rest.T(), err)
	expectedHeaderValue := fmt.Sprintf("LINK url=https://auth.localhost.io/api/token/link?for=%s, description=\"%s token is missing. Link %s account\"", for_, providerName, providerName)
	assert.Contains(rest.T(), rw.Header().Get("WWW-Authenticate"), expectedHeaderValue)
	assert.Contains(rest.T(), rw.Header().Get("Access-Control-Expose-Headers"), "WWW-Authenticate")
}

// This test demonstrates that the token status works successfully without the ForcePull option
// However, when the ForcePull option is passed, we determine that the token is invalid.
func (rest *TestTokenStorageREST) TestStatusExternalTokenInvalidOnForcePullInternalError() {
	identity := rest.statusExternalGitHubTokenFromDBSuccess("linked")
	rest.checkStatusExternalTokenInvalidOnForcePullInternalError(identity, "https://github.com/a/b", "github")
	rest.checkStatusExternalTokenInvalidOnForcePullInternalError(identity, "github", "github")

	identity = rest.statusExternalOSOTokenFromDBSuccess("linked")
	rest.checkStatusExternalTokenInvalidOnForcePullInternalError(identity, "https://api.starter-us-east-2a.openshift.com", "openshift-v3")
	rest.checkStatusExternalTokenInvalidOnForcePullInternalError(identity, "openshift", "openshift-v3")
}

func (rest *TestTokenStorageREST) checkStatusExternalTokenInvalidOnForcePullInternalError(identity account.Identity, for_, providerName string) {
	// Token status is OK, but when tested with provider it's invalid.
	forcePull := true
	rest.dummyProviderConfigFactory.LoadProfileFail = true
	service, controller := rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)
	rw, _ := test.StatusTokenUnauthorized(rest.T(), service.Context, service, controller, for_, &forcePull)
	assert.Equal(rest.T(), rw.Header().Get("WWW-Authenticate"), fmt.Sprintf("LINK url=http:///api/token/link?for=%s, description=\"%s token is not valid or expired. Relink %s account\"", for_, providerName, providerName))
	assert.Contains(rest.T(), rw.Header().Get("Access-Control-Expose-Headers"), "WWW-Authenticate")
}

// This test demonstrates that the token status works successfully without the ForcePull option
// When the ForcePull option is passed, we determine that the token is valid.
func (rest *TestTokenStorageREST) TestStatusExternalTokenValidOnForcePullInternalError() {
	identity, err := testsupport.CreateTestIdentity(rest.DB, uuid.NewV4().String(), "KC")
	require.Nil(rest.T(), err)
	rest.checkStatusExternalTokenValidOnForcePullInternalError(identity, "https://github.com/a/b", "https://github.com")
	rest.checkStatusExternalTokenValidOnForcePullInternalError(identity, "github", "https://github.com")
	rest.checkStatusExternalTokenValidOnForcePullInternalError(identity, "openshift", "https://api.starter-us-east-2.openshift.com")
	rest.checkStatusExternalTokenValidOnForcePullInternalError(identity, "https://api.starter-us-east-2.openshift.com", "https://api.starter-us-east-2.openshift.com")
}

func (rest *TestTokenStorageREST) checkStatusExternalTokenValidOnForcePullInternalError(identity account.Identity, for_, expectedProviderURL string) {
	rest.mockKeycloakExternalTokenServiceClient.scenario = "linked"
	service, controller := rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}
	providerConfig, err := rest.providerConfigFactory.NewOauthProvider(context.Background(), identity.ID, r, for_)
	require.Nil(rest.T(), err)

	expectedToken := provider.ExternalToken{
		ProviderID: providerConfig.ID(),
		Scope:      providerConfig.Scopes(),
		IdentityID: identity.ID,
		Token:      "1234-from-db",
		Username:   "1234-from-dbtestuser",
	}
	rest.externalTokenRepository.Create(context.Background(), &expectedToken)

	test.StatusTokenOK(rest.T(), service.Context, service, controller, for_, nil)

	// Token status is OK and when tested with provider it's valid.
	forcePull := true
	rest.dummyProviderConfigFactory.LoadProfileFail = false
	service, controller = rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)
	_, tokenStatus := test.StatusTokenOK(rest.T(), service.Context, service, controller, for_, &forcePull)
	rest.assertTokenStatus(expectedToken.Username, expectedProviderURL, tokenStatus)
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
	test.DeleteTokenUnauthorized(rest.T(), service.Context, service, controller, "github")
	test.DeleteTokenUnauthorized(rest.T(), service.Context, service, controller, "https://api.starter-us-east-2.openshift.com")
	test.DeleteTokenUnauthorized(rest.T(), service.Context, service, controller, "openshift")
}

func (rest *TestTokenStorageREST) TestDeleteExternalTokenOK() {
	rest.deleteExternalTokenOK("https://github.com/a/b")
	rest.deleteExternalTokenOK("github")
	rest.deleteExternalTokenOK("https://api.starter-us-east-2.openshift.com")
	rest.deleteExternalTokenOK("openshift")
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
	providerConfig, err := rest.providerConfigFactory.NewOauthProvider(context.Background(), identity.ID, r, forResource)
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
		Scope:       "admin:repo_hook read:org repo user gist",
		TokenType:   "bearer",
	}
}

func positiveKCResponseOpenShift() *keycloak.KeycloakExternalTokenResponse {
	return &keycloak.KeycloakExternalTokenResponse{
		AccessToken: "1234-openshift",
		Scope:       "user:full",
		TokenType:   "bearer",
	}
}
