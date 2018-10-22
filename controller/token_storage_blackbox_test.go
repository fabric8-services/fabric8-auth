package controller_test

import (
	"context"
	"fmt"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/factory"
	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	tokenrepo "github.com/fabric8-services/fabric8-auth/authorization/token/repository"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestTokenStorageREST struct {
	gormtestsupport.DBTestSuite
	identityRepository      account.IdentityRepository
	externalTokenRepository tokenrepo.ExternalTokenRepository
	userRepository          account.UserRepository

	providerConfigFactory      provider.OauthProviderFactory
	dummyProviderConfigFactory *testsupport.DummyProviderFactory
	clusterServiceMock         service.ClusterService
}

func TestRunTokenStorageREST(t *testing.T) {
	suite.Run(t, &TestTokenStorageREST{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (rest *TestTokenStorageREST) SetupSuite() {
	rest.DBTestSuite.SetupSuite()
	rest.clusterServiceMock = testsupport.NewClusterServiceMock(rest.T())
	rest.Application = gormapplication.NewGormDB(rest.DB, rest.Configuration, factory.WithClusterService(rest.clusterServiceMock))
}

func (rest *TestTokenStorageREST) SetupTest() {
	rest.DBTestSuite.SetupTest()
	rest.identityRepository = account.NewIdentityRepository(rest.DB)
	rest.externalTokenRepository = tokenrepo.NewExternalTokenRepository(rest.DB)
	rest.userRepository = account.NewUserRepository(rest.DB)
	rest.providerConfigFactory = link.NewOauthProviderFactory(rest.Configuration, rest.Application)
	rest.dummyProviderConfigFactory = &testsupport.DummyProviderFactory{Token: uuid.NewV4().String(), Config: rest.Configuration, App: rest.Application}
}

func (rest *TestTokenStorageREST) UnSecuredController() (*goa.Service, *TokenController) {
	svc := testsupport.ServiceAsUser("Token-Service", testsupport.TestIdentity)
	loginService := newTestKeycloakOAuthProvider(rest.Application)
	return svc, &TokenController{Controller: svc.NewController("token"), Configuration: rest.Configuration}
}

func (rest *TestTokenStorageREST) SecuredControllerWithIdentity(identity account.Identity) (*goa.Service, *TokenController) {
	loginService := newTestKeycloakOAuthProvider(rest.Application)

	svc := testsupport.ServiceAsUser("Token-Service", identity)
	return svc, NewTokenController(svc, rest.Application, loginService, &DummyLinkService{}, rest.providerConfigFactory, manager.TokenManager, rest.Configuration)
}

func (rest *TestTokenStorageREST) SecuredControllerWithIdentityAndDummyProviderFactory(identity account.Identity) (*goa.Service, *TokenController) {
	loginService := newTestKeycloakOAuthProvider(rest.Application)

	svc := testsupport.ServiceAsUser("Token-Service", identity)
	return svc, NewTokenController(svc, rest.Application, loginService.TokenManager, rest.Configuration)
}

func (rest *TestTokenStorageREST) SecuredControllerWithServiceAccount(serviceAccount account.Identity) (*goa.Service, *TokenController) {
	loginService := newTestKeycloakOAuthProvider(rest.Application)

	svc := testsupport.ServiceAsServiceAccountUser("Token-Service", serviceAccount)
	return svc, NewTokenController(svc, rest.Application, loginService.TokenManager, rest.Configuration)
}

func (rest *TestTokenStorageREST) SecuredControllerWithServiceAccountAndDummyProviderFactory(serviceAccount account.Identity) (*goa.Service, *TokenController) {
	loginService := newTestKeycloakOAuthProvider(rest.Application)

	svc := testsupport.ServiceAsServiceAccountUser("Token-Service", serviceAccount)
	return svc, NewTokenController(svc, rest.Application, loginService.TokenManager, rest.Configuration)
}

func (rest *TestTokenStorageREST) TestRetrieveOSOServiceAccountTokenOK() {
	rest.checkRetrieveOSOServiceAccountToken("fabric8-oso-proxy")
	rest.checkRetrieveOSOServiceAccountToken("fabric8-tenant")
	rest.checkRetrieveOSOServiceAccountToken("fabric8-jenkins-idler")
	rest.checkRetrieveOSOServiceAccountToken("fabric8-jenkins-proxy")
}

func (rest *TestTokenStorageREST) checkRetrieveOSOServiceAccountToken(saName string) {
	sa := account.Identity{
		Username: saName,
	}
	service, controller := rest.SecuredControllerWithServiceAccount(sa)
	clusters, err := rest.clusterServiceMock.Clusters(nil)
	require.NoError(rest.T(), err)
	require.NotEmpty(rest.T(), clusters)
	for _, cluster := range clusters {
		_, tokenResponse := test.RetrieveTokenOK(rest.T(), service.Context, service, controller, cluster.APIURL, nil)

		assert.Equal(rest.T(), cluster.ServiceAccountToken, tokenResponse.AccessToken)
		assert.Equal(rest.T(), "<unknown>", tokenResponse.Scope)
		assert.Equal(rest.T(), "bearer", tokenResponse.TokenType)
		require.NotNil(rest.T(), tokenResponse.Username)
		assert.Equal(rest.T(), "dsaas", tokenResponse.Username)
		assert.Equal(rest.T(), cluster.APIURL, tokenResponse.ProviderAPIURL)
	}
}

func (rest *TestTokenStorageREST) TestRetrieveOSOServiceAccountTokenValidOnForcePull() {
	rest.checkRetrieveOSOServiceAccountTokenValidOnForcePull("fabric8-oso-proxy")
	rest.checkRetrieveOSOServiceAccountTokenValidOnForcePull("fabric8-tenant")
}

func (rest *TestTokenStorageREST) checkRetrieveOSOServiceAccountTokenValidOnForcePull(saName string) {
	sa := account.Identity{
		Username: saName,
	}

	rest.dummyProviderConfigFactory.LoadProfileFail = false
	service, controller := rest.SecuredControllerWithServiceAccountAndDummyProviderFactory(sa)

	clusters, err := rest.clusterServiceMock.Clusters(nil)
	require.NoError(rest.T(), err)
	require.NotEmpty(rest.T(), clusters)
	forcePull := true

	for _, cluster := range clusters {
		_, tokenResponse := test.RetrieveTokenOK(rest.T(), service.Context, service, controller, cluster.APIURL, &forcePull)

		assert.Equal(rest.T(), cluster.ServiceAccountToken, tokenResponse.AccessToken)
		assert.Equal(rest.T(), "<unknown>", tokenResponse.Scope)
		assert.Equal(rest.T(), "bearer", tokenResponse.TokenType)
		require.NotNil(rest.T(), tokenResponse.Username)
		assert.Equal(rest.T(), tokenResponse.AccessToken+"testuser", tokenResponse.Username)
		assert.Equal(rest.T(), cluster.APIURL, tokenResponse.ProviderAPIURL)
	}
}

func (rest *TestTokenStorageREST) TestRetrieveOSOServiceAccountTokenInvalidOnForcePull() {
	rest.checkRetrieveOSOServiceAccountTokenInvalidOnForcePull("fabric8-oso-proxy")
	rest.checkRetrieveOSOServiceAccountTokenInvalidOnForcePull("fabric8-tenant")
}

func (rest *TestTokenStorageREST) checkRetrieveOSOServiceAccountTokenInvalidOnForcePull(saName string) {
	sa := account.Identity{
		Username: saName,
	}
	rest.dummyProviderConfigFactory.LoadProfileFail = true

	service, controller := rest.SecuredControllerWithServiceAccountAndDummyProviderFactory(sa)
	forcePull := true
	clusters, err := rest.clusterServiceMock.Clusters(nil)
	require.NoError(rest.T(), err)
	require.NotEmpty(rest.T(), clusters)

	for _, cluster := range clusters {
		// Token status is OK, but when tested with provider it's invalid.
		test.RetrieveTokenOK(rest.T(), service.Context, service, controller, cluster.APIURL, nil)
		rw, _ := test.RetrieveTokenUnauthorized(rest.T(), service.Context, service, controller, cluster.APIURL, &forcePull)
		assert.Equal(rest.T(), fmt.Sprintf("LINK description=\"%s cluster token is not valid or expired", cluster.APIURL), rw.Header().Get("WWW-Authenticate"))
		assert.Contains(rest.T(), "WWW-Authenticate", rw.Header().Get("Access-Control-Expose-Headers"))
	}
}

func (rest *TestTokenStorageREST) TestRetrieveOSOServiceAccountTokenForUnknownSAFails() {
	sa := account.Identity{
		Username: "unknown-sa",
	}
	clusters, err := rest.clusterServiceMock.Clusters(nil)
	require.NoError(rest.T(), err)
	require.NotEmpty(rest.T(), clusters)

	service, controller := rest.SecuredControllerWithServiceAccount(sa)
	for _, cluster := range clusters {
		test.RetrieveTokenUnauthorized(rest.T(), service.Context, service, controller, cluster.APIURL, nil)
	}
}

// Not present in DB
func (rest *TestTokenStorageREST) TestRetrieveExternalTokenUnauthorized() {
	rest.checkRetrieveExternalTokenUnauthorized("https://github.com/sbose78", "github")
	rest.checkRetrieveExternalTokenUnauthorized("github", "github")
	rest.checkRetrieveExternalTokenUnauthorized("https://api.starter-us-east-2.openshift.com", "openshift-v3")
	rest.checkRetrieveExternalTokenUnauthorized("openshift", "openshift-v3")
}

func (rest *TestTokenStorageREST) checkRetrieveExternalTokenUnauthorized(for_ string, providerName string) {
	identity, err := testsupport.CreateTestIdentity(rest.DB, uuid.NewV4().String(), "KC")
	require.Nil(rest.T(), err)

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

	service, controller := rest.SecuredControllerWithIdentity(identity)
	test.RetrieveTokenUnauthorized(rest.T(), service.Context, service, controller, "https://github.com/a/b", nil)
	test.RetrieveTokenUnauthorized(rest.T(), service.Context, service, controller, "github", nil)
	test.RetrieveTokenUnauthorized(rest.T(), service.Context, service, controller, "https://api.starter-us-east-2.openshift.com", nil)
	test.RetrieveTokenUnauthorized(rest.T(), service.Context, service, controller, "openshift", nil)
}

// Present in DB.
func (rest *TestTokenStorageREST) TestRetrieveExternalTokenPresentInDB() {
	rest.retrieveExternalGitHubTokenFromDBSuccess()
	rest.retrieveExternalOSOTokenFromDBSuccess()
}

func (rest *TestTokenStorageREST) retrieveExternalGitHubTokenFromDBSuccess() (account.Identity, tokenrepo.ExternalToken) {
	identity, err := testsupport.CreateTestIdentity(rest.DB, uuid.NewV4().String(), "KC")
	require.Nil(rest.T(), err)

	service, controller := rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}
	providerConfig, err := rest.providerConfigFactory.NewOauthProvider(context.Background(), identity.ID, r, "https://github.com/a/b")
	require.Nil(rest.T(), err)

	expectedToken := tokenrepo.ExternalToken{
		ProviderID: providerConfig.ID(),
		Scope:      providerConfig.Scopes(),
		IdentityID: identity.ID,
		Token:      "1234-from-db",
		Username:   "1234-from-dbtestuser",
	}
	rest.externalTokenRepository.Create(context.Background(), &expectedToken)

	// This call should have a positive retrieval from the database.
	_, tokenResponse := test.RetrieveTokenOK(rest.T(), service.Context, service, controller, "https://github.com/a/b", nil)
	require.Equal(rest.T(), expectedToken.Token, tokenResponse.AccessToken)
	require.Equal(rest.T(), expectedToken.Scope, tokenResponse.Scope)
	require.Equal(rest.T(), expectedToken.Username, tokenResponse.Username)
	require.Equal(rest.T(), "bearer", tokenResponse.TokenType)
	require.Equal(rest.T(), "https://github.com", tokenResponse.ProviderAPIURL)

	// Alias
	_, tokenResponse = test.RetrieveTokenOK(rest.T(), service.Context, service, controller, "github", nil)
	require.Equal(rest.T(), expectedToken.Token, tokenResponse.AccessToken)
	require.Equal(rest.T(), expectedToken.Scope, tokenResponse.Scope)
	require.Equal(rest.T(), expectedToken.Username, tokenResponse.Username)
	require.Equal(rest.T(), "bearer", tokenResponse.TokenType)
	require.Equal(rest.T(), "https://github.com", tokenResponse.ProviderAPIURL)

	return identity, expectedToken
}

func (rest *TestTokenStorageREST) retrieveExternalOSOTokenFromDBSuccess() (account.Identity, tokenrepo.ExternalToken) {
	identity, err := testsupport.CreateTestIdentityAndUserWithDefaultProviderType(rest.DB, uuid.NewV4().String())
	require.Nil(rest.T(), err)

	service, controller := rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}
	providerConfig, err := rest.providerConfigFactory.NewOauthProvider(context.Background(), identity.ID, r, "https://api.starter-us-east-2a.openshift.com")
	require.Nil(rest.T(), err)

	expectedToken := tokenrepo.ExternalToken{
		ProviderID: providerConfig.ID(),
		Scope:      providerConfig.Scopes(),
		IdentityID: identity.ID,
		Token:      "1234-from-db",
		Username:   "1234-from-dbtestuser",
	}
	rest.externalTokenRepository.Create(context.Background(), &expectedToken)

	// This call should have a positive retrieval from the database.
	_, tokenResponse := test.RetrieveTokenOK(rest.T(), service.Context, service, controller, "https://api.starter-us-east-2a.openshift.com", nil)
	require.Equal(rest.T(), expectedToken.Token, tokenResponse.AccessToken)
	require.Equal(rest.T(), expectedToken.Scope, tokenResponse.Scope)
	require.Equal(rest.T(), expectedToken.Username, tokenResponse.Username)
	require.Equal(rest.T(), "bearer", tokenResponse.TokenType)
	require.Equal(rest.T(), "https://api.starter-us-east-2a.openshift.com/", tokenResponse.ProviderAPIURL)

	// Alias
	_, tokenResponse = test.RetrieveTokenOK(rest.T(), service.Context, service, controller, "openshift", nil)
	require.Equal(rest.T(), expectedToken.Token, tokenResponse.AccessToken)
	require.Equal(rest.T(), expectedToken.Scope, tokenResponse.Scope)
	require.Equal(rest.T(), expectedToken.Username, tokenResponse.Username)
	require.Equal(rest.T(), "bearer", tokenResponse.TokenType)
	require.Equal(rest.T(), "https://api.starter-us-east-2a.openshift.com/", tokenResponse.ProviderAPIURL)

	return identity, expectedToken
}

func (rest *TestTokenStorageREST) TestRetrieveExternalTokenForDeprovisionedUserUnauthorized() {
	identity, err := testsupport.CreateDeprovisionedTestIdentityAndUser(rest.DB, "TestRetrieveExternalTokenForDeprovisionedUserUnauthorized"+uuid.NewV4().String())
	require.Nil(rest.T(), err)

	service, controller := rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}
	providerConfig, err := rest.providerConfigFactory.NewOauthProvider(context.Background(), identity.ID, r, "https://github.com/a/b")
	require.Nil(rest.T(), err)

	storedToken := tokenrepo.ExternalToken{
		ProviderID: providerConfig.ID(),
		Scope:      providerConfig.Scopes(),
		IdentityID: identity.ID,
		Token:      "1234-from-db",
		Username:   "1234-from-dbtestuser",
	}
	rest.externalTokenRepository.Create(context.Background(), &storedToken)

	test.RetrieveTokenUnauthorized(rest.T(), service.Context, service, controller, "https://github.com/a/b", nil)
	test.StatusTokenUnauthorized(rest.T(), service.Context, service, controller, "https://github.com/a/b", nil)
}

func (rest *TestTokenStorageREST) TestRetrieveExternalTokenBadRequest() {
	identity := testsupport.TestIdentity
	service, controller := rest.SecuredControllerWithIdentity(identity)
	test.RetrieveTokenBadRequest(rest.T(), service.Context, service, controller, "", nil)
}

// This test demonstrates that the token retrieval works successfully without the ForcePull option
// However, when the ForcePull option is passed, we determine that the token is invalid.
func (rest *TestTokenStorageREST) TestRetrieveExternalTokenInvalidOnForcePullInternalError() {
	identity, _ := rest.retrieveExternalGitHubTokenFromDBSuccess()
	rest.checkRetrieveExternalTokenInvalidOnForcePullInternalError(identity, "https://github.com/a/b", "github")
	rest.checkRetrieveExternalTokenInvalidOnForcePullInternalError(identity, "github", "github")

	identity, _ = rest.retrieveExternalOSOTokenFromDBSuccess()
	rest.checkRetrieveExternalTokenInvalidOnForcePullInternalError(identity, "https://api.starter-us-east-2a.openshift.com", "openshift-v3")
	rest.checkRetrieveExternalTokenInvalidOnForcePullInternalError(identity, "openshift", "openshift-v3")
}

func (rest *TestTokenStorageREST) checkRetrieveExternalTokenInvalidOnForcePullInternalError(identity account.Identity, for_, providerName string) {
	// Token status is OK, but when tested with provider it's invalid.
	forcePull := true
	rest.dummyProviderConfigFactory.LoadProfileFail = true
	service, controller := rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)
	test.RetrieveTokenOK(rest.T(), service.Context, service, controller, for_, nil)
	rw, _ := test.RetrieveTokenUnauthorized(rest.T(), service.Context, service, controller, for_, &forcePull)
	assert.Equal(rest.T(), fmt.Sprintf("LINK url=http:///api/token/link?for=%s, description=\"%s token is not valid or expired. Relink %s account\"", for_, providerName, providerName), rw.Header().Get("WWW-Authenticate"))
	assert.Contains(rest.T(), "WWW-Authenticate", rw.Header().Get("Access-Control-Expose-Headers"))
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

	service, controller := rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}
	providerConfig, err := rest.providerConfigFactory.NewOauthProvider(context.Background(), identity.ID, r, for_)
	require.Nil(rest.T(), err)

	expectedToken := tokenrepo.ExternalToken{
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

func (rest *TestTokenStorageREST) assertTokenStatus(expectedUsername, expectedURL string, actualStatus *app.ExternalTokenStatus) {
	require.NotNil(rest.T(), actualStatus)
	assert.Equal(rest.T(), expectedUsername, actualStatus.Username)
	assert.Equal(rest.T(), expectedURL, actualStatus.ProviderAPIURL)
}

// Present in DB.
func (rest *TestTokenStorageREST) TestStatusExternalTokenPresentInDB() {
	rest.statusExternalGitHubTokenFromDBSuccess()
	rest.statusExternalOSOTokenFromDBSuccess()
}

func (rest *TestTokenStorageREST) statusExternalGitHubTokenFromDBSuccess() account.Identity {
	identity, _ := rest.retrieveExternalGitHubTokenFromDBSuccess()
	service, controller := rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)

	_, tokenStatus := test.StatusTokenOK(rest.T(), service.Context, service, controller, "https://github.com/a/b", nil)
	rest.assertTokenStatus("1234-from-dbtestuser", "https://github.com", tokenStatus)

	_, tokenStatus = test.StatusTokenOK(rest.T(), service.Context, service, controller, "github", nil)
	rest.assertTokenStatus("1234-from-dbtestuser", "https://github.com", tokenStatus)

	return identity
}

func (rest *TestTokenStorageREST) statusExternalOSOTokenFromDBSuccess() account.Identity {
	identity, _ := rest.retrieveExternalOSOTokenFromDBSuccess()
	service, controller := rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)

	_, tokenStatus := test.StatusTokenOK(rest.T(), service.Context, service, controller, "https://api.starter-us-east-2a.openshift.com", nil)
	rest.assertTokenStatus("1234-from-dbtestuser", "https://api.starter-us-east-2a.openshift.com/", tokenStatus)

	_, tokenStatus = test.StatusTokenOK(rest.T(), service.Context, service, controller, "openshift", nil)
	rest.assertTokenStatus("1234-from-dbtestuser", "https://api.starter-us-east-2a.openshift.com/", tokenStatus)

	return identity
}

// Not present in DB
func (rest *TestTokenStorageREST) TestStatusExternalTokenUnauthorized() {
	rest.checkStatusExternalTokenUnauthorized("https://github.com/sbose78", "github")
	rest.checkStatusExternalTokenUnauthorized("github", "github")
	rest.checkStatusExternalTokenUnauthorized("https://api.starter-us-east-2.openshift.com", "openshift-v3")
	rest.checkStatusExternalTokenUnauthorized("openshift", "openshift-v3")
}

func (rest *TestTokenStorageREST) checkStatusExternalTokenUnauthorized(for_ string, providerName string) {
	identity, err := testsupport.CreateTestIdentity(rest.DB, uuid.NewV4().String(), "KC")
	require.Nil(rest.T(), err)

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
	identity := rest.statusExternalGitHubTokenFromDBSuccess()
	rest.checkStatusExternalTokenInvalidOnForcePullInternalError(identity, "https://github.com/a/b", "github")
	rest.checkStatusExternalTokenInvalidOnForcePullInternalError(identity, "github", "github")

	identity = rest.statusExternalOSOTokenFromDBSuccess()
	rest.checkStatusExternalTokenInvalidOnForcePullInternalError(identity, "https://api.starter-us-east-2a.openshift.com", "openshift-v3")
	rest.checkStatusExternalTokenInvalidOnForcePullInternalError(identity, "openshift", "openshift-v3")
}

func (rest *TestTokenStorageREST) checkStatusExternalTokenInvalidOnForcePullInternalError(identity account.Identity, for_, providerName string) {
	// Token status is OK, but when tested with provider it's invalid.
	forcePull := true
	rest.dummyProviderConfigFactory.LoadProfileFail = true
	service, controller := rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)
	test.RetrieveTokenOK(rest.T(), service.Context, service, controller, for_, nil)
	rw, _ := test.StatusTokenUnauthorized(rest.T(), service.Context, service, controller, for_, &forcePull)
	assert.Equal(rest.T(), fmt.Sprintf("LINK url=http:///api/token/link?for=%s, description=\"%s token is not valid or expired. Relink %s account\"", for_, providerName, providerName), rw.Header().Get("WWW-Authenticate"))
	assert.Contains(rest.T(), "WWW-Authenticate", rw.Header().Get("Access-Control-Expose-Headers"))
}

// This test demonstrates that the token status works successfully without the ForcePull option
// When the ForcePull option is passed, we determine that the token is valid.
func (rest *TestTokenStorageREST) TestStatusExternalTokenValidOnForcePullInternalError() {
	identity, err := testsupport.CreateTestIdentity(rest.DB, uuid.NewV4().String(), "KC")
	require.Nil(rest.T(), err)
	rest.checkStatusExternalTokenValidOnForcePullInternalError(identity, "https://github.com/a/b", "https://github.com")
	rest.checkStatusExternalTokenValidOnForcePullInternalError(identity, "github", "https://github.com")
	rest.checkStatusExternalTokenValidOnForcePullInternalError(identity, "openshift", "https://api.starter-us-east-2.openshift.com/")
	rest.checkStatusExternalTokenValidOnForcePullInternalError(identity, "https://api.starter-us-east-2.openshift.com", "https://api.starter-us-east-2.openshift.com/")
}

func (rest *TestTokenStorageREST) checkStatusExternalTokenValidOnForcePullInternalError(identity account.Identity, for_, expectedProviderURL string) {

	service, controller := rest.SecuredControllerWithIdentityAndDummyProviderFactory(identity)

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}
	providerConfig, err := rest.providerConfigFactory.NewOauthProvider(context.Background(), identity.ID, r, for_)
	require.Nil(rest.T(), err)

	expectedToken := tokenrepo.ExternalToken{
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
	service, controller := rest.SecuredControllerWithIdentity(identity)
	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}
	providerConfig, err := rest.providerConfigFactory.NewOauthProvider(context.Background(), identity.ID, r, forResource)
	require.Nil(rest.T(), err)

	// OK is returned even if there is nothing to delete
	test.DeleteTokenOK(rest.T(), service.Context, service, controller, forResource)

	for i := 0; i < numberOfTokens; i++ {
		expectedToken := tokenrepo.ExternalToken{
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
