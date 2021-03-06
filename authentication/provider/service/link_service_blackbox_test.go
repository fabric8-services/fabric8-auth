package service_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/fabric8-services/fabric8-auth/authentication/provider"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/factory"
	"github.com/fabric8-services/fabric8-auth/application/transaction"
	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	token "github.com/fabric8-services/fabric8-auth/authorization/token/repository"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/fabric8-services/fabric8-auth/test"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type LinkTestSuite struct {
	gormtestsupport.DBTestSuite
	testIdentity       account.Identity
	requestData        *goa.RequestData
	clusterServiceMock service.ClusterService
}

func TestRunLinkTestSuite(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &LinkTestSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *LinkTestSuite) SetupSuite() {
	s.DBTestSuite.SetupSuite()

	s.clusterServiceMock = testsupport.NewClusterServiceMock(s.T())
	s.Application = gormapplication.NewGormDB(s.DB, s.Configuration, s.Wrappers, factory.WithClusterService(s.clusterServiceMock))
	s.requestData = &goa.RequestData{Request: &http.Request{
		URL: &url.URL{Scheme: "https", Host: "auth.openshift.io"},
	}}
}

func (s *LinkTestSuite) SetupTest() {
	s.DBTestSuite.SetupTest()
	var err error
	s.testIdentity, err = test.CreateTestIdentity(s.DB, "TestLinkSuite user", "test provider")
	require.Nil(s.T(), err)
}

func (s *LinkTestSuite) TestInvalidRedirectFails() {
	existingValidRedirects := os.Getenv("AUTH_REDIRECT_VALID")
	defer func() {
		os.Setenv("AUTH_REDIRECT_VALID", existingValidRedirects)
		config, err := configuration.GetConfigurationData()
		require.Nil(s.T(), err)
		s.Configuration = config
	}()
	os.Setenv("AUTH_REDIRECT_VALID", configuration.DefaultValidRedirectURLs)

	_, err := s.Application.LinkService().ProviderLocation(context.Background(), s.requestData, s.testIdentity.ID.String(), "https://github.com/org/repo", "https://some.host.com")
	require.Error(s.T(), err)

	_, err = s.Application.LinkService().ProviderLocation(context.Background(), s.requestData, s.testIdentity.ID.String(), "https://github.com/org/repo", "not_a_url")
	require.Error(s.T(), err)
}

func (s *LinkTestSuite) TestUnknownProviderFails() {
	_, err := s.Application.LinkService().ProviderLocation(context.Background(), s.requestData, s.testIdentity.ID.String(), "https://unknown.provider.com/org/repo", "https://openshift.io/home")
	require.NotNil(s.T(), err)
}

func (s *LinkTestSuite) TestCallbackWithUnknownStateFails() {
	_, err := s.Application.LinkService().Callback(context.Background(), s.requestData, "randomState", "randomCode")
	require.NotNil(s.T(), err)
}

func (s *LinkTestSuite) TestGitHubProviderRedirectsToAuthorize() {
	s.checkGitHubProviderRedirectsToAuthorize("https://github.com")
	s.checkGitHubProviderRedirectsToAuthorize("https://github.com/")
	s.checkGitHubProviderRedirectsToAuthorize("https://github.com/org/repo")
	// Check alias
	s.checkGitHubProviderRedirectsToAuthorize("github")
}

func (s *LinkTestSuite) checkGitHubProviderRedirectsToAuthorize(for_ string) {
	location, err := s.Application.LinkService().ProviderLocation(context.Background(), s.requestData, s.testIdentity.ID.String(), for_, "https://openshift.io/home")
	require.Nil(s.T(), err)
	require.True(s.T(), strings.HasPrefix(location, "https://github.com/login/oauth/authorize"))
	require.NotEmpty(s.T(), s.stateParam(location))
}

func (s *LinkTestSuite) TestOSOProviderRedirectsToAuthorize() {
	s.checkOSOProviderRedirectsToAuthorize(s.Configuration.GetOpenShiftClientApiUrl())
	s.checkOSOProviderRedirectsToAuthorize("https://api.starter-us-east-2.openshift.com")
	s.checkOSOProviderRedirectsToAuthorize("https://api.starter-us-east-2.openshift.com/")
	s.checkOSOProviderRedirectsToAuthorize("https://api.starter-us-east-2.openshift.com/path")
	s.checkOSO2aProviderRedirectsToAuthorize(s.testIdentity, "https://api.starter-us-east-2a.openshift.com/path")
	// Check alias
	s.checkOSOProviderRedirectsToAuthorize("openshift")

	// Check another cluster
	testIdentityCluster2a, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "testOSOProviderRedirectsToAuthoentication/account/repositoryrizeUser")
	require.Nil(s.T(), err)
	s.checkOSO2aProviderRedirectsToAuthorize(testIdentityCluster2a, "openshift")
}

func (s *LinkTestSuite) checkOSOProviderRedirectsToAuthorize(for_ string) {
	location, err := s.Application.LinkService().ProviderLocation(context.Background(), s.requestData, s.testIdentity.ID.String(), for_, "https://openshift.io/home")
	require.Nil(s.T(), err)
	require.Contains(s.T(), location, fmt.Sprintf("%s/oauth/authorize", s.Configuration.GetOpenShiftClientApiUrl()))
	require.NotEmpty(s.T(), s.stateParam(location))
}

func (s *LinkTestSuite) checkOSO2aProviderRedirectsToAuthorize(identity account.Identity, for_ string) {
	location, err := s.Application.LinkService().ProviderLocation(context.Background(), s.requestData, identity.ID.String(), for_, "https://openshift.io/home")
	require.Nil(s.T(), err)
	require.Contains(s.T(), location, "https://api.starter-us-east-2a.openshift.com/oauth/authorize")
	require.NotEmpty(s.T(), s.stateParam(location))
}

func (s *LinkTestSuite) TestMultipleProvidersRedirectsToAuthorize() {
	location, err := s.Application.LinkService().ProviderLocation(context.Background(), s.requestData, s.testIdentity.ID.String(), "https://github.com/org/repo,https://openshift.io/home", "https://openshift.io/_home")
	require.Nil(s.T(), err)
	require.True(s.T(), strings.HasPrefix(location, "https://github.com/login/oauth/authorize"))
	require.NotEmpty(s.T(), s.stateParam(location))

	// Aliases
	location, err = s.Application.LinkService().ProviderLocation(context.Background(), s.requestData, s.testIdentity.ID.String(), "github,openshift", "https://openshift.io/_home")
	require.Nil(s.T(), err)
	require.True(s.T(), strings.HasPrefix(location, "https://github.com/login/oauth/authorize"))
	require.NotEmpty(s.T(), s.stateParam(location))
}

func (s *LinkTestSuite) stateParam(location string) string {
	locationURL, err := url.Parse(location)
	require.Nil(s.T(), err)
	allQueryParameters := locationURL.Query()
	require.NotNil(s.T(), allQueryParameters)
	require.NotNil(s.T(), allQueryParameters["state"])
	require.NotNil(s.T(), allQueryParameters["state"][0])
	return allQueryParameters["state"][0]
}

func (s *LinkTestSuite) TestCallbackFailsForUnknownIdentity() {
	location, err := s.Application.LinkService().ProviderLocation(context.Background(), s.requestData, uuid.NewV4().String(), "https://github.com/org/repo", "https://openshift.io/home")
	require.Nil(s.T(), err)
	state := s.stateParam(location)

	code := uuid.NewV4().String()
	_, err = s.Application.LinkService().Callback(context.Background(), s.requestData, state, code)
	require.NotNil(s.T(), err)
}

func (s *LinkTestSuite) TestProviderSavesTokenOK() {
	location, err := s.Application.LinkService().ProviderLocation(context.Background(), s.requestData, s.testIdentity.ID.String(), "https://github.com/org/repo", "https://openshift.io/home")
	require.Nil(s.T(), err)
	state := s.stateParam(location)

	token := uuid.NewV4().String()
	testsupport.ActivateDummyLinkingProviderFactory(s, s.Configuration, token, false, "")

	code := uuid.NewV4().String()
	callbackLocation, err := s.Application.LinkService().Callback(context.Background(), s.requestData, state, code)
	require.Nil(s.T(), err)
	require.Contains(s.T(), callbackLocation, "https://openshift.io/home")

	s.checkToken(provider.GitHubProviderID, token)
}

func (s *LinkTestSuite) TestProviderSavesTokenWithUnavailableProfileFails() {
	location, err := s.Application.LinkService().ProviderLocation(context.Background(), s.requestData, s.testIdentity.ID.String(), "https://github.com/org/repo", "https://openshift.io/home")
	require.Nil(s.T(), err)
	state := s.stateParam(location)

	code := uuid.NewV4().String()
	testsupport.ActivateDummyLinkingProviderFactory(s, s.Configuration, uuid.NewV4().String(), true, "")
	_, err = s.Application.LinkService().Callback(context.Background(), s.requestData, state, code)
	require.NotNil(s.T(), err)
	require.Contains(s.T(), err.Error(), "unable to load profile")
}

func (s *LinkTestSuite) TestProviderSavesTokensForMultipleResources() {
	// Redirect to GitHub first
	location, err := s.Application.LinkService().ProviderLocation(context.Background(), s.requestData, s.testIdentity.ID.String(), "https://github.com/org/repo,https://api.starter-us-east-2.openshift.com", "https://openshift.io/_home")
	require.Nil(s.T(), err)
	locationURL, err := url.Parse(location)
	require.Nil(s.T(), err)
	require.Equal(s.T(), "https", locationURL.Scheme)
	require.Equal(s.T(), "github.com", locationURL.Host)
	require.Equal(s.T(), "/login/oauth/authorize", locationURL.Path)

	// Callback from GitHub should redirect to OSO
	callbackLocation := s.checkCallback(provider.GitHubProviderID, s.stateParam(location), url.URL{Scheme: "https", Host: "api.starter-us-east-2.openshift.com", Path: "/oauth/authorize"})

	// Callback from OSO should redirect back to the original redirect URL
	cls, err := s.clusterServiceMock.ClusterByURL(context.Background(), "https://api.starter-us-east-2.openshift.com")
	require.NoError(s.T(), err)
	require.NotNil(s.T(), cls)
	s.checkCallback(cls.TokenProviderID, s.stateParam(callbackLocation), url.URL{Scheme: "https", Host: "openshift.io", Path: "/_home"})
}

func (s *LinkTestSuite) TestProviderSavesTokensForMultipleAliases() {
	// Redirect to GitHub first
	location, err := s.Application.LinkService().ProviderLocation(context.Background(), s.requestData, s.testIdentity.ID.String(), "github,openshift", "https://openshift.io/_home")
	require.Nil(s.T(), err)
	locationURL, err := url.Parse(location)
	require.Nil(s.T(), err)
	require.Equal(s.T(), "https", locationURL.Scheme)
	require.Equal(s.T(), "github.com", locationURL.Host)
	require.Equal(s.T(), "/login/oauth/authorize", locationURL.Path)

	// Callback from GitHub should redirect to OSO
	callbackLocation := s.checkCallback(provider.GitHubProviderID, s.stateParam(location), url.URL{Scheme: "https", Host: "api.starter-us-east-2.openshift.com", Path: "/oauth/authorize"})

	// Callback from OSO should redirect back to the original redirect URL
	cls, err := s.clusterServiceMock.ClusterByURL(context.Background(), "https://api.starter-us-east-2.openshift.com")
	require.NoError(s.T(), err)
	require.NotNil(s.T(), cls)
	s.checkCallback(cls.TokenProviderID, s.stateParam(callbackLocation), url.URL{Scheme: "https", Host: "openshift.io", Path: "/_home"})
}

func (s *LinkTestSuite) checkCallback(providerID string, state string, expectedURL url.URL) string {
	token := uuid.NewV4().String()
	testsupport.ActivateDummyLinkingProviderFactory(s, s.Configuration, token, false, "")
	callbackLocation, err := s.Application.LinkService().Callback(context.Background(), s.requestData, state, uuid.NewV4().String())
	require.Nil(s.T(), err)
	locationURL, err := url.Parse(callbackLocation)
	require.Nil(s.T(), err)
	require.Equal(s.T(), expectedURL.Scheme, locationURL.Scheme)
	require.Equal(s.T(), expectedURL.Host, locationURL.Host)
	require.Equal(s.T(), expectedURL.Path, locationURL.Path)

	s.checkToken(providerID, token)
	return callbackLocation
}

func (s *LinkTestSuite) checkToken(providerID string, expectedToken string) {
	id, err := uuid.FromString(providerID)
	require.Nil(s.T(), err)
	var tokens []token.ExternalToken
	err = transaction.Transactional(s.Application, func(tr transaction.TransactionalResources) error {
		tokens, err = tr.ExternalTokens().LoadByProviderIDAndIdentityID(context.Background(), id, s.testIdentity.ID)
		return err
	})
	require.Nil(s.T(), err)
	require.Equal(s.T(), 1, len(tokens))
	require.Equal(s.T(), expectedToken, tokens[0].Token)
	require.Equal(s.T(), expectedToken+"testuser", tokens[0].Username)
}
