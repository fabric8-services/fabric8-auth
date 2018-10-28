package controller_test

import (
	"context"
	"fmt"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/rest"
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

type TokenStorageTestSuite struct {
	gormtestsupport.DBTestSuite
	identityRepository      account.IdentityRepository
	externalTokenRepository tokenrepo.ExternalTokenRepository
	userRepository          account.UserRepository

	clusterServiceMock service.ClusterService
	tokenManager       manager.TokenManager
}

func TestTokenStorageController(t *testing.T) {
	suite.Run(t, &TokenStorageTestSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *TokenStorageTestSuite) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	s.clusterServiceMock = testsupport.NewClusterServiceMock(s.T())
	s.Application = gormapplication.NewGormDB(s.DB, s.Configuration, s.Wrappers, factory.WithClusterService(s.clusterServiceMock))
	tm, err := manager.DefaultManager(s.Configuration)
	require.NoError(s.T(), err)
	s.tokenManager = tm
}

func (s *TokenStorageTestSuite) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.identityRepository = account.NewIdentityRepository(s.DB)
	s.externalTokenRepository = tokenrepo.NewExternalTokenRepository(s.DB)
	s.userRepository = account.NewUserRepository(s.DB)
}

func (s *TokenStorageTestSuite) UnSecuredController() (*goa.Service, *TokenController) {
	svc := testsupport.ServiceAsUser("Token-Service", testsupport.TestIdentity)
	return svc, &TokenController{Controller: svc.NewController("token"), Configuration: s.Configuration}
}

func (s *TokenStorageTestSuite) SecuredControllerWithIdentity(identity account.Identity) (*goa.Service, *TokenController) {
	svc := testsupport.ServiceAsUser("Token-Service", identity)
	return svc, NewTokenController(svc, s.Application, s.tokenManager, s.Configuration)
}

func (s *TokenStorageTestSuite) SecuredControllerWithIdentityAndDummyProviderFactory(identity account.Identity) (*goa.Service, *TokenController) {
	svc := testsupport.ServiceAsUser("Token-Service", identity)
	return svc, NewTokenController(svc, s.Application, s.tokenManager, s.Configuration)
}

func (s *TokenStorageTestSuite) SecuredControllerWithServiceAccount(serviceAccount account.Identity) (*goa.Service, *TokenController) {
	svc := testsupport.ServiceAsServiceAccountUser("Token-Service", serviceAccount)
	return svc, NewTokenController(svc, s.Application, s.tokenManager, s.Configuration)
}

func (s *TokenStorageTestSuite) SecuredControllerWithServiceAccountAndDummyProviderFactory(serviceAccount account.Identity) (*goa.Service, *TokenController) {
	svc := testsupport.ServiceAsServiceAccountUser("Token-Service", serviceAccount)
	return svc, NewTokenController(svc, s.Application, s.tokenManager, s.Configuration)
}

func (s *TokenStorageTestSuite) TestRetrieveOSOServiceAccountTokenOK() {
	s.checkRetrieveOSOServiceAccountToken("fabric8-oso-proxy")
	s.checkRetrieveOSOServiceAccountToken("fabric8-tenant")
	s.checkRetrieveOSOServiceAccountToken("fabric8-jenkins-idler")
	s.checkRetrieveOSOServiceAccountToken("fabric8-jenkins-proxy")
}

func (s *TokenStorageTestSuite) checkRetrieveOSOServiceAccountToken(saName string) {
	sa := account.Identity{
		Username: saName,
	}
	service, controller := s.SecuredControllerWithServiceAccount(sa)
	clusters, err := s.clusterServiceMock.Clusters(nil)
	require.NoError(s.T(), err)
	require.NotEmpty(s.T(), clusters)
	for _, cluster := range clusters {
		_, tokenResponse := test.RetrieveTokenOK(s.T(), service.Context, service, controller, cluster.APIURL, nil)

		assert.Equal(s.T(), cluster.ServiceAccountToken, tokenResponse.AccessToken)
		assert.Equal(s.T(), "<unknown>", tokenResponse.Scope)
		assert.Equal(s.T(), "bearer", tokenResponse.TokenType)
		require.NotNil(s.T(), tokenResponse.Username)
		assert.Equal(s.T(), "dsaas", tokenResponse.Username)
		assert.Equal(s.T(), cluster.APIURL, tokenResponse.ProviderAPIURL)
	}
}

func (s *TokenStorageTestSuite) TestRetrieveOSOServiceAccountTokenValidOnForcePull() {
	s.checkRetrieveOSOServiceAccountTokenValidOnForcePull("fabric8-oso-proxy")
	s.checkRetrieveOSOServiceAccountTokenValidOnForcePull("fabric8-tenant")
}

func (s *TokenStorageTestSuite) checkRetrieveOSOServiceAccountTokenValidOnForcePull(saName string) {
	sa := account.Identity{
		Username: saName,
	}

	testsupport.ActivateDummyLinkingProviderFactory(s, s.Configuration, uuid.NewV4().String())
	service, controller := s.SecuredControllerWithServiceAccountAndDummyProviderFactory(sa)

	clusters, err := s.clusterServiceMock.Clusters(nil)
	require.NoError(s.T(), err)
	require.NotEmpty(s.T(), clusters)
	forcePull := true

	for _, cluster := range clusters {
		_, tokenResponse := test.RetrieveTokenOK(s.T(), service.Context, service, controller, cluster.APIURL, &forcePull)

		assert.Equal(s.T(), cluster.ServiceAccountToken, tokenResponse.AccessToken)
		assert.Equal(s.T(), "<unknown>", tokenResponse.Scope)
		assert.Equal(s.T(), "bearer", tokenResponse.TokenType)
		require.NotNil(s.T(), tokenResponse.Username)
		assert.Equal(s.T(), tokenResponse.AccessToken+"testuser", tokenResponse.Username)
		assert.Equal(s.T(), cluster.APIURL, tokenResponse.ProviderAPIURL)
	}
}

func (s *TokenStorageTestSuite) TestRetrieveOSOServiceAccountTokenInvalidOnForcePull() {
	s.checkRetrieveOSOServiceAccountTokenInvalidOnForcePull("fabric8-oso-proxy")
	s.checkRetrieveOSOServiceAccountTokenInvalidOnForcePull("fabric8-tenant")
}

func (s *TokenStorageTestSuite) checkRetrieveOSOServiceAccountTokenInvalidOnForcePull(saName string) {
	sa := account.Identity{
		Username: saName,
	}
	testsupport.ActivateDummyLinkingProviderFactory(s, s.Configuration, uuid.NewV4().String())
	service, controller := s.SecuredControllerWithServiceAccountAndDummyProviderFactory(sa)
	forcePull := true
	clusters, err := s.clusterServiceMock.Clusters(nil)
	require.NoError(s.T(), err)
	require.NotEmpty(s.T(), clusters)

	for _, cluster := range clusters {
		// Token status is OK, but when tested with provider it's invalid.
		test.RetrieveTokenOK(s.T(), service.Context, service, controller, cluster.APIURL, nil)
		rw, _ := test.RetrieveTokenUnauthorized(s.T(), service.Context, service, controller, cluster.APIURL, &forcePull)
		assert.Equal(s.T(), fmt.Sprintf("LINK description=\"%s cluster token is not valid or expired", cluster.APIURL), rw.Header().Get("WWW-Authenticate"))
		assert.Contains(s.T(), "WWW-Authenticate", rw.Header().Get("Access-Control-Expose-Headers"))
	}
}

func (s *TokenStorageTestSuite) TestRetrieveOSOServiceAccountTokenForUnknownSAFails() {
	sa := account.Identity{
		Username: "unknown-sa",
	}
	clusters, err := s.clusterServiceMock.Clusters(nil)
	require.NoError(s.T(), err)
	require.NotEmpty(s.T(), clusters)

	service, controller := s.SecuredControllerWithServiceAccount(sa)
	for _, cluster := range clusters {
		test.RetrieveTokenUnauthorized(s.T(), service.Context, service, controller, cluster.APIURL, nil)
	}
}

// Not present in DB
func (s *TokenStorageTestSuite) TestRetrieveExternalTokenUnauthorized() {
	s.checkRetrieveExternalTokenUnauthorized("https://github.com/sbose78", "github")
	s.checkRetrieveExternalTokenUnauthorized("github", "github")
	s.checkRetrieveExternalTokenUnauthorized("https://api.starter-us-east-2.openshift.com", "openshift-v3")
	s.checkRetrieveExternalTokenUnauthorized("openshift", "openshift-v3")
}

func (s *TokenStorageTestSuite) checkRetrieveExternalTokenUnauthorized(for_ string, providerName string) {
	identity, err := testsupport.CreateTestIdentity(s.DB, uuid.NewV4().String(), "KC")
	require.Nil(s.T(), err)

	service, controller := s.SecuredControllerWithIdentity(identity)

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
	require.Nil(s.T(), err)

	err = controller.Retrieve(tokenCtx)
	require.NotNil(s.T(), err)
	expectedHeaderValue := fmt.Sprintf("LINK url=https://auth.localhost.io/api/token/link?for=%s, description=\"%s token is missing. Link %s account\"", for_, providerName, providerName)
	assert.Contains(s.T(), rw.Header().Get("WWW-Authenticate"), expectedHeaderValue)
	assert.Contains(s.T(), rw.Header().Get("Access-Control-Expose-Headers"), "WWW-Authenticate")
}

// Identity does not exist.
func (s *TokenStorageTestSuite) TestRetrieveExternalTokenIdentityNotPresent() {
	// using an Identity which does not exist in the database.
	identity := account.Identity{
		ID:       uuid.NewV4(),
		Username: "TestDeveloper",
	}

	service, controller := s.SecuredControllerWithIdentity(identity)
	test.RetrieveTokenUnauthorized(s.T(), service.Context, service, controller, "https://github.com/a/b", nil)
	test.RetrieveTokenUnauthorized(s.T(), service.Context, service, controller, "github", nil)
	test.RetrieveTokenUnauthorized(s.T(), service.Context, service, controller, "https://api.starter-us-east-2.openshift.com", nil)
	test.RetrieveTokenUnauthorized(s.T(), service.Context, service, controller, "openshift", nil)
}

// Present in DB.
func (s *TokenStorageTestSuite) TestRetrieveExternalTokenPresentInDB() {
	s.retrieveExternalGitHubTokenFromDBSuccess()
	s.retrieveExternalOSOTokenFromDBSuccess()
}

func (s *TokenStorageTestSuite) retrieveExternalGitHubTokenFromDBSuccess() (account.Identity, tokenrepo.ExternalToken) {
	identity, err := testsupport.CreateTestIdentity(s.DB, uuid.NewV4().String(), "KC")
	require.Nil(s.T(), err)

	service, controller := s.SecuredControllerWithIdentityAndDummyProviderFactory(identity)

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}

	providerConfig, err := s.Application.LinkService().(servicecontext.ServiceContext).Factories().LinkingProviderFactory().NewLinkingProvider(
		context.Background(), identity.ID, rest.AbsoluteURL(r, "", nil), "https://github.com/a/b")

	//providerConfig, err := rest.Application.LinkingProviderFactory().NewLinkingProvider(context.Background(), identity.ID, r, "https://github.com/a/b")
	require.Nil(s.T(), err)

	expectedToken := tokenrepo.ExternalToken{
		ProviderID: providerConfig.ID(),
		Scope:      providerConfig.Scopes(),
		IdentityID: identity.ID,
		Token:      "1234-from-db",
		Username:   "1234-from-dbtestuser",
	}
	s.externalTokenRepository.Create(context.Background(), &expectedToken)

	// This call should have a positive retrieval from the database.
	_, tokenResponse := test.RetrieveTokenOK(s.T(), service.Context, service, controller, "https://github.com/a/b", nil)
	require.Equal(s.T(), expectedToken.Token, tokenResponse.AccessToken)
	require.Equal(s.T(), expectedToken.Scope, tokenResponse.Scope)
	require.Equal(s.T(), expectedToken.Username, tokenResponse.Username)
	require.Equal(s.T(), "bearer", tokenResponse.TokenType)
	require.Equal(s.T(), "https://github.com", tokenResponse.ProviderAPIURL)

	// Alias
	_, tokenResponse = test.RetrieveTokenOK(s.T(), service.Context, service, controller, "github", nil)
	require.Equal(s.T(), expectedToken.Token, tokenResponse.AccessToken)
	require.Equal(s.T(), expectedToken.Scope, tokenResponse.Scope)
	require.Equal(s.T(), expectedToken.Username, tokenResponse.Username)
	require.Equal(s.T(), "bearer", tokenResponse.TokenType)
	require.Equal(s.T(), "https://github.com", tokenResponse.ProviderAPIURL)

	return identity, expectedToken
}

func (s *TokenStorageTestSuite) retrieveExternalOSOTokenFromDBSuccess() (account.Identity, tokenrepo.ExternalToken) {
	identity, err := testsupport.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, uuid.NewV4().String())
	require.Nil(s.T(), err)

	service, controller := s.SecuredControllerWithIdentityAndDummyProviderFactory(identity)

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}
	providerConfig, err := s.Application.LinkService().(servicecontext.ServiceContext).Factories().LinkingProviderFactory().NewLinkingProvider(
		context.Background(),
		identity.ID, rest.AbsoluteURL(r, "", nil), "https://api.starter-us-east-2a.openshift.com")
	require.Nil(s.T(), err)

	expectedToken := tokenrepo.ExternalToken{
		ProviderID: providerConfig.ID(),
		Scope:      providerConfig.Scopes(),
		IdentityID: identity.ID,
		Token:      "1234-from-db",
		Username:   "1234-from-dbtestuser",
	}
	s.externalTokenRepository.Create(context.Background(), &expectedToken)

	// This call should have a positive retrieval from the database.
	_, tokenResponse := test.RetrieveTokenOK(s.T(), service.Context, service, controller, "https://api.starter-us-east-2a.openshift.com", nil)
	require.Equal(s.T(), expectedToken.Token, tokenResponse.AccessToken)
	require.Equal(s.T(), expectedToken.Scope, tokenResponse.Scope)
	require.Equal(s.T(), expectedToken.Username, tokenResponse.Username)
	require.Equal(s.T(), "bearer", tokenResponse.TokenType)
	require.Equal(s.T(), "https://api.starter-us-east-2a.openshift.com/", tokenResponse.ProviderAPIURL)

	// Alias
	_, tokenResponse = test.RetrieveTokenOK(s.T(), service.Context, service, controller, "openshift", nil)
	require.Equal(s.T(), expectedToken.Token, tokenResponse.AccessToken)
	require.Equal(s.T(), expectedToken.Scope, tokenResponse.Scope)
	require.Equal(s.T(), expectedToken.Username, tokenResponse.Username)
	require.Equal(s.T(), "bearer", tokenResponse.TokenType)
	require.Equal(s.T(), "https://api.starter-us-east-2a.openshift.com/", tokenResponse.ProviderAPIURL)

	return identity, expectedToken
}

func (s *TokenStorageTestSuite) TestRetrieveExternalTokenForDeprovisionedUserUnauthorized() {
	identity, err := testsupport.CreateDeprovisionedTestIdentityAndUser(s.DB, "TestRetrieveExternalTokenForDeprovisionedUserUnauthorized"+uuid.NewV4().String())
	require.Nil(s.T(), err)

	service, controller := s.SecuredControllerWithIdentityAndDummyProviderFactory(identity)

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}
	providerConfig, err := s.Application.LinkService().(servicecontext.ServiceContext).Factories().LinkingProviderFactory().NewLinkingProvider(
		context.Background(), identity.ID, rest.AbsoluteURL(r, "", nil), "https://github.com/a/b")
	require.Nil(s.T(), err)

	storedToken := tokenrepo.ExternalToken{
		ProviderID: providerConfig.ID(),
		Scope:      providerConfig.Scopes(),
		IdentityID: identity.ID,
		Token:      "1234-from-db",
		Username:   "1234-from-dbtestuser",
	}
	s.externalTokenRepository.Create(context.Background(), &storedToken)

	test.RetrieveTokenUnauthorized(s.T(), service.Context, service, controller, "https://github.com/a/b", nil)
	test.StatusTokenUnauthorized(s.T(), service.Context, service, controller, "https://github.com/a/b", nil)
}

func (s *TokenStorageTestSuite) TestRetrieveExternalTokenBadRequest() {
	identity := testsupport.TestIdentity
	service, controller := s.SecuredControllerWithIdentity(identity)
	test.RetrieveTokenBadRequest(s.T(), service.Context, service, controller, "", nil)
}

// This test demonstrates that the token retrieval works successfully without the ForcePull option
// However, when the ForcePull option is passed, we determine that the token is invalid.
func (s *TokenStorageTestSuite) TestRetrieveExternalTokenInvalidOnForcePullInternalError() {
	identity, _ := s.retrieveExternalGitHubTokenFromDBSuccess()
	s.checkRetrieveExternalTokenInvalidOnForcePullInternalError(identity, "https://github.com/a/b", "github")
	s.checkRetrieveExternalTokenInvalidOnForcePullInternalError(identity, "github", "github")

	identity, _ = s.retrieveExternalOSOTokenFromDBSuccess()
	s.checkRetrieveExternalTokenInvalidOnForcePullInternalError(identity, "https://api.starter-us-east-2a.openshift.com", "openshift-v3")
	s.checkRetrieveExternalTokenInvalidOnForcePullInternalError(identity, "openshift", "openshift-v3")
}

func (s *TokenStorageTestSuite) checkRetrieveExternalTokenInvalidOnForcePullInternalError(identity account.Identity, for_, providerName string) {
	// Token status is OK, but when tested with provider it's invalid.
	forcePull := true
	testsupport.ActivateDummyLinkingProviderFactory(s, s.Configuration, uuid.NewV4().String())
	service, controller := s.SecuredControllerWithIdentityAndDummyProviderFactory(identity)
	test.RetrieveTokenOK(s.T(), service.Context, service, controller, for_, nil)
	rw, _ := test.RetrieveTokenUnauthorized(s.T(), service.Context, service, controller, for_, &forcePull)
	assert.Equal(s.T(), fmt.Sprintf("LINK url=http:///api/token/link?for=%s, description=\"%s token is not valid or expired. Relink %s account\"", for_, providerName, providerName), rw.Header().Get("WWW-Authenticate"))
	assert.Contains(s.T(), "WWW-Authenticate", rw.Header().Get("Access-Control-Expose-Headers"))
}

// This test demonstrates that the token retrieval works successfully without the ForcePull option
// When the ForcePull option is passed, we determine that the token is invalid.

func (s *TokenStorageTestSuite) TestRetrieveExternalTokenValidOnForcePullInternalError() {
	identity, err := testsupport.CreateTestIdentity(s.DB, uuid.NewV4().String(), "KC")
	require.Nil(s.T(), err)

	s.checkRetrieveExternalTokenValidOnForcePullInternalError(identity, "https://github.com/a/b")
	s.checkRetrieveExternalTokenValidOnForcePullInternalError(identity, "github")
	s.checkRetrieveExternalTokenValidOnForcePullInternalError(identity, "https://api.starter-us-east-2.openshift.com")
	s.checkRetrieveExternalTokenValidOnForcePullInternalError(identity, "openshift")
}

func (s *TokenStorageTestSuite) checkRetrieveExternalTokenValidOnForcePullInternalError(identity account.Identity, for_ string) {

	service, controller := s.SecuredControllerWithIdentityAndDummyProviderFactory(identity)

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}
	providerConfig, err := s.Application.LinkService().(servicecontext.ServiceContext).Factories().LinkingProviderFactory().NewLinkingProvider(
		context.Background(), identity.ID, rest.AbsoluteURL(r, "", nil), for_)
	require.Nil(s.T(), err)

	expectedToken := tokenrepo.ExternalToken{
		ProviderID: providerConfig.ID(),
		Scope:      providerConfig.Scopes(),
		IdentityID: identity.ID,
		Token:      "1234-from-db",
		Username:   "1234-from-dbtestuser",
	}
	s.externalTokenRepository.Create(context.Background(), &expectedToken)

	test.RetrieveTokenOK(s.T(), service.Context, service, controller, for_, nil)

	// Token retrieved from database is successful and when tested with github it's valid.
	forcePull := true
	testsupport.ActivateDummyLinkingProviderFactory(s, s.Configuration, uuid.NewV4().String())
	service, controller = s.SecuredControllerWithIdentityAndDummyProviderFactory(identity)
	test.RetrieveTokenOK(s.T(), service.Context, service, controller, for_, &forcePull)
}

func (s *TokenStorageTestSuite) assertTokenStatus(expectedUsername, expectedURL string, actualStatus *app.ExternalTokenStatus) {
	require.NotNil(s.T(), actualStatus)
	assert.Equal(s.T(), expectedUsername, actualStatus.Username)
	assert.Equal(s.T(), expectedURL, actualStatus.ProviderAPIURL)
}

// Present in DB.
func (s *TokenStorageTestSuite) TestStatusExternalTokenPresentInDB() {
	s.statusExternalGitHubTokenFromDBSuccess()
	s.statusExternalOSOTokenFromDBSuccess()
}

func (s *TokenStorageTestSuite) statusExternalGitHubTokenFromDBSuccess() account.Identity {
	identity, _ := s.retrieveExternalGitHubTokenFromDBSuccess()
	service, controller := s.SecuredControllerWithIdentityAndDummyProviderFactory(identity)

	_, tokenStatus := test.StatusTokenOK(s.T(), service.Context, service, controller, "https://github.com/a/b", nil)
	s.assertTokenStatus("1234-from-dbtestuser", "https://github.com", tokenStatus)

	_, tokenStatus = test.StatusTokenOK(s.T(), service.Context, service, controller, "github", nil)
	s.assertTokenStatus("1234-from-dbtestuser", "https://github.com", tokenStatus)

	return identity
}

func (s *TokenStorageTestSuite) statusExternalOSOTokenFromDBSuccess() account.Identity {
	identity, _ := s.retrieveExternalOSOTokenFromDBSuccess()
	service, controller := s.SecuredControllerWithIdentityAndDummyProviderFactory(identity)

	_, tokenStatus := test.StatusTokenOK(s.T(), service.Context, service, controller, "https://api.starter-us-east-2a.openshift.com", nil)
	s.assertTokenStatus("1234-from-dbtestuser", "https://api.starter-us-east-2a.openshift.com/", tokenStatus)

	_, tokenStatus = test.StatusTokenOK(s.T(), service.Context, service, controller, "openshift", nil)
	s.assertTokenStatus("1234-from-dbtestuser", "https://api.starter-us-east-2a.openshift.com/", tokenStatus)

	return identity
}

// Not present in DB
func (s *TokenStorageTestSuite) TestStatusExternalTokenUnauthorized() {
	s.checkStatusExternalTokenUnauthorized("https://github.com/sbose78", "github")
	s.checkStatusExternalTokenUnauthorized("github", "github")
	s.checkStatusExternalTokenUnauthorized("https://api.starter-us-east-2.openshift.com", "openshift-v3")
	s.checkStatusExternalTokenUnauthorized("openshift", "openshift-v3")
}

func (s *TokenStorageTestSuite) checkStatusExternalTokenUnauthorized(for_ string, providerName string) {
	identity, err := testsupport.CreateTestIdentity(s.DB, uuid.NewV4().String(), "KC")
	require.Nil(s.T(), err)

	service, controller := s.SecuredControllerWithIdentity(identity)

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
	require.Nil(s.T(), err)

	err = controller.Status(tokenCtx)
	require.NotNil(s.T(), err)
	expectedHeaderValue := fmt.Sprintf("LINK url=https://auth.localhost.io/api/token/link?for=%s, description=\"%s token is missing. Link %s account\"", for_, providerName, providerName)
	assert.Contains(s.T(), rw.Header().Get("WWW-Authenticate"), expectedHeaderValue)
	assert.Contains(s.T(), rw.Header().Get("Access-Control-Expose-Headers"), "WWW-Authenticate")
}

// This test demonstrates that the token status works successfully without the ForcePull option
// However, when the ForcePull option is passed, we determine that the token is invalid.
func (s *TokenStorageTestSuite) TestStatusExternalTokenInvalidOnForcePullInternalError() {
	identity := s.statusExternalGitHubTokenFromDBSuccess()
	s.checkStatusExternalTokenInvalidOnForcePullInternalError(identity, "https://github.com/a/b", "github")
	s.checkStatusExternalTokenInvalidOnForcePullInternalError(identity, "github", "github")

	identity = s.statusExternalOSOTokenFromDBSuccess()
	s.checkStatusExternalTokenInvalidOnForcePullInternalError(identity, "https://api.starter-us-east-2a.openshift.com", "openshift-v3")
	s.checkStatusExternalTokenInvalidOnForcePullInternalError(identity, "openshift", "openshift-v3")
}

func (s *TokenStorageTestSuite) checkStatusExternalTokenInvalidOnForcePullInternalError(identity account.Identity, for_, providerName string) {
	// Token status is OK, but when tested with provider it's invalid.
	forcePull := true
	testsupport.ActivateDummyLinkingProviderFactory(s, s.Configuration, uuid.NewV4().String())
	service, controller := s.SecuredControllerWithIdentityAndDummyProviderFactory(identity)
	test.RetrieveTokenOK(s.T(), service.Context, service, controller, for_, nil)
	rw, _ := test.StatusTokenUnauthorized(s.T(), service.Context, service, controller, for_, &forcePull)
	assert.Equal(s.T(), fmt.Sprintf("LINK url=http:///api/token/link?for=%s, description=\"%s token is not valid or expired. Relink %s account\"", for_, providerName, providerName), rw.Header().Get("WWW-Authenticate"))
	assert.Contains(s.T(), "WWW-Authenticate", rw.Header().Get("Access-Control-Expose-Headers"))
}

// This test demonstrates that the token status works successfully without the ForcePull option
// When the ForcePull option is passed, we determine that the token is valid.
func (s *TokenStorageTestSuite) TestStatusExternalTokenValidOnForcePullInternalError() {
	identity, err := testsupport.CreateTestIdentity(s.DB, uuid.NewV4().String(), "KC")
	require.Nil(s.T(), err)
	s.checkStatusExternalTokenValidOnForcePullInternalError(identity, "https://github.com/a/b", "https://github.com")
	s.checkStatusExternalTokenValidOnForcePullInternalError(identity, "github", "https://github.com")
	s.checkStatusExternalTokenValidOnForcePullInternalError(identity, "openshift", "https://api.starter-us-east-2.openshift.com/")
	s.checkStatusExternalTokenValidOnForcePullInternalError(identity, "https://api.starter-us-east-2.openshift.com", "https://api.starter-us-east-2.openshift.com/")
}

func (s *TokenStorageTestSuite) checkStatusExternalTokenValidOnForcePullInternalError(identity account.Identity, for_, expectedProviderURL string) {

	service, controller := s.SecuredControllerWithIdentityAndDummyProviderFactory(identity)

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}
	providerConfig, err := s.Application.LinkService().(servicecontext.ServiceContext).Factories().LinkingProviderFactory().NewLinkingProvider(
		context.Background(), identity.ID, rest.AbsoluteURL(r, "", nil), for_)
	require.Nil(s.T(), err)

	expectedToken := tokenrepo.ExternalToken{
		ProviderID: providerConfig.ID(),
		Scope:      providerConfig.Scopes(),
		IdentityID: identity.ID,
		Token:      "1234-from-db",
		Username:   "1234-from-dbtestuser",
	}
	s.externalTokenRepository.Create(context.Background(), &expectedToken)

	test.StatusTokenOK(s.T(), service.Context, service, controller, for_, nil)

	// Token status is OK and when tested with provider it's valid.
	forcePull := true
	testsupport.ActivateDummyLinkingProviderFactory(s, s.Configuration, uuid.NewV4().String())
	service, controller = s.SecuredControllerWithIdentityAndDummyProviderFactory(identity)
	_, tokenStatus := test.StatusTokenOK(s.T(), service.Context, service, controller, for_, &forcePull)
	s.assertTokenStatus(expectedToken.Username, expectedProviderURL, tokenStatus)
}

func (s *TokenStorageTestSuite) TestDeleteExternalTokenBadRequest() {
	identity := testsupport.TestIdentity
	service, controller := s.SecuredControllerWithIdentity(identity)
	test.DeleteTokenBadRequest(s.T(), service.Context, service, controller, "")
}

func (s *TokenStorageTestSuite) TestDeleteExternalTokenIdentityNotPresent() {
	identity := testsupport.TestIdentity // using an Identity which has no existence the database.

	service, controller := s.SecuredControllerWithIdentity(identity)
	test.DeleteTokenUnauthorized(s.T(), service.Context, service, controller, "https://github.com/a/b")
	test.DeleteTokenUnauthorized(s.T(), service.Context, service, controller, "github")
	test.DeleteTokenUnauthorized(s.T(), service.Context, service, controller, "https://api.starter-us-east-2.openshift.com")
	test.DeleteTokenUnauthorized(s.T(), service.Context, service, controller, "openshift")
}

func (s *TokenStorageTestSuite) TestDeleteExternalTokenOK() {
	s.deleteExternalTokenOK("https://github.com/a/b")
	s.deleteExternalTokenOK("github")
	s.deleteExternalTokenOK("https://api.starter-us-east-2.openshift.com")
	s.deleteExternalTokenOK("openshift")
}

func (s *TokenStorageTestSuite) deleteExternalTokenOK(forResource string) {
	s.deleteExternalToken(forResource, 1, "unlinked")
	s.deleteExternalToken(forResource, 1, "positive")
	s.deleteExternalToken(forResource, 1, "internalError")
	s.deleteExternalToken(forResource, 3, "unlinked")
	s.deleteExternalToken(forResource, 3, "positive")
	s.deleteExternalToken(forResource, 3, "internalError")
}

func (s *TokenStorageTestSuite) deleteExternalToken(forResource string, numberOfTokens int, scenario string) {
	identity, err := testsupport.CreateTestIdentity(s.DB, uuid.NewV4().String(), "KC")
	require.Nil(s.T(), err)
	service, controller := s.SecuredControllerWithIdentity(identity)
	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}
	providerConfig, err := s.Application.LinkService().(servicecontext.ServiceContext).Factories().LinkingProviderFactory().NewLinkingProvider(
		context.Background(), identity.ID, rest.AbsoluteURL(r, "", nil), forResource)
	require.Nil(s.T(), err)

	// OK is returned even if there is nothing to delete
	test.DeleteTokenOK(s.T(), service.Context, service, controller, forResource)

	for i := 0; i < numberOfTokens; i++ {
		expectedToken := tokenrepo.ExternalToken{
			ProviderID: providerConfig.ID(),
			Scope:      providerConfig.Scopes(),
			IdentityID: identity.ID,
			Token:      "1234-from-db",
		}
		err = s.externalTokenRepository.Create(context.Background(), &expectedToken)
		require.Nil(s.T(), err)
	}
	tokens, err := s.Application.ExternalTokens().LoadByProviderIDAndIdentityID(service.Context, providerConfig.ID(), identity.ID)
	require.Nil(s.T(), err)
	require.Equal(s.T(), numberOfTokens, len(tokens))

	test.DeleteTokenOK(s.T(), service.Context, service, controller, forResource)
	tokens, err = s.Application.ExternalTokens().LoadByProviderIDAndIdentityID(service.Context, providerConfig.ID(), identity.ID)
	require.Nil(s.T(), err)
	require.Empty(s.T(), tokens)
}
