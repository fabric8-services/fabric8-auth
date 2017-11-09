package link

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/fabric8-services/fabric8-auth/test"
	"github.com/fabric8-services/fabric8-auth/token/provider"

	"os"

	"strings"

	"github.com/goadesign/goa"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	netcontext "golang.org/x/net/context"
	"golang.org/x/oauth2"
)

type LinkTestSuite struct {
	gormtestsupport.DBTestSuite
	application  application.DB
	linkService  LinkOAuthService
	testIdentity account.Identity
	requestData  *goa.RequestData
}

func TestRunLinkTestSuite(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &LinkTestSuite{DBTestSuite: gormtestsupport.NewDBTestSuite("")})
}

func (s *LinkTestSuite) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	s.application = gormapplication.NewGormDB(s.DB)
	providerFactory := NewOauthProviderFactory(s.Configuration)
	s.linkService = NewLinkServiceWithFactory(s.Configuration, s.application, providerFactory)
	var err error
	s.testIdentity, err = test.CreateTestIdentity(s.DB, "TestLinkSuite user", "test provider")
	require.Nil(s.T(), err)
	s.requestData = &goa.RequestData{Request: &http.Request{
		URL: &url.URL{Scheme: "https", Host: "auth.openshift.io"},
	}}
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

	_, err := s.linkService.ProviderLocation(context.Background(), s.requestData, s.testIdentity.ID.String(), "https://github.com/org/repo", "https://some.host.com")
	require.NotNil(s.T(), err)
}

func (s *LinkTestSuite) TestUnknownProviderFails() {
	_, err := s.linkService.ProviderLocation(context.Background(), s.requestData, s.testIdentity.ID.String(), "https://unknown.provider.com/org/repo", "https://openshift.io/home")
	require.NotNil(s.T(), err)
}

func (s *LinkTestSuite) TestCallbackWithUnknownStateFails() {
	_, err := s.linkService.Callback(context.Background(), s.requestData, "randomState", "randomCode")
	require.NotNil(s.T(), err)
}

func (s *LinkTestSuite) TestGitHubProviderRedirectsToAuthorize() {
	location, err := s.linkService.ProviderLocation(context.Background(), s.requestData, s.testIdentity.ID.String(), "https://github.com/org/repo", "https://openshift.io/home")
	require.Nil(s.T(), err)
	require.True(s.T(), strings.HasPrefix(location, "https://github.com/login/oauth/authorize"))
	require.NotEmpty(s.T(), s.stateParam(location))
}

func (s *LinkTestSuite) TestOSOProviderRedirectsToAuthorize() {
	location, err := s.linkService.ProviderLocation(context.Background(), s.requestData, s.testIdentity.ID.String(), s.Configuration.GetOpenShiftClientApiUrl(), "https://openshift.io/home")
	require.Nil(s.T(), err)
	require.Contains(s.T(), location, fmt.Sprintf("%s/oauth/authorize", s.Configuration.GetOpenShiftClientApiUrl()))
	require.NotEmpty(s.T(), s.stateParam(location))
}

func (s *LinkTestSuite) TestMultipleProvidersRedirectsToAuthorize() {
	location, err := s.linkService.ProviderLocation(context.Background(), s.requestData, s.testIdentity.ID.String(), "https://github.com/org/repo,https://openshift.io/home", "https://openshift.io/_home")
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
	location, err := s.linkService.ProviderLocation(context.Background(), s.requestData, uuid.NewV4().String(), "https://github.com/org/repo", "https://openshift.io/home")
	require.Nil(s.T(), err)
	state := s.stateParam(location)

	linkServiceWithDummyProviderFactory := NewLinkServiceWithFactory(s.Configuration, gormapplication.NewGormDB(s.DB), &DummyProviderFactory{uuid.NewV4().String()})

	code := uuid.NewV4().String()
	_, err = linkServiceWithDummyProviderFactory.Callback(context.Background(), s.requestData, state, code)
	require.NotNil(s.T(), err)
}

func (s *LinkTestSuite) TestProviderSavesToken() {
	location, err := s.linkService.ProviderLocation(context.Background(), s.requestData, s.testIdentity.ID.String(), "https://github.com/org/repo", "https://openshift.io/home")
	require.Nil(s.T(), err)
	state := s.stateParam(location)

	token := uuid.NewV4().String()
	linkServiceWithDummyProviderFactory := NewLinkServiceWithFactory(s.Configuration, gormapplication.NewGormDB(s.DB), &DummyProviderFactory{token})

	code := uuid.NewV4().String()
	callbackLocation, err := linkServiceWithDummyProviderFactory.Callback(context.Background(), s.requestData, state, code)
	require.Nil(s.T(), err)
	require.Contains(s.T(), callbackLocation, "https://openshift.io/home")

	s.checkToken(gitHubProviderID, token)
}

func (s *LinkTestSuite) TestProviderSavesTokensForMultipleResources() {
	// Redirect to GitHub first
	location, err := s.linkService.ProviderLocation(context.Background(), s.requestData, s.testIdentity.ID.String(), "https://github.com/org/repo,https://api.starter-us-east-2.openshift.com", "https://openshift.io/_home")
	require.Nil(s.T(), err)
	locationURL, err := url.Parse(location)
	require.Nil(s.T(), err)
	require.Equal(s.T(), "https", locationURL.Scheme)
	require.Equal(s.T(), "github.com", locationURL.Host)
	require.Equal(s.T(), "/login/oauth/authorize", locationURL.Path)

	// Callback from GitHub should redirect to OSO
	callbackLocation := s.checkCallback(gitHubProviderID, s.stateParam(location), url.URL{Scheme: "https", Host: "api.starter-us-east-2.openshift.com", Path: "/oauth/authorize"})

	// Callback from OSO should redirect back to the original redirect URL
	s.checkCallback(osoStarterEast2ProviderID, s.stateParam(callbackLocation), url.URL{Scheme: "https", Host: "openshift.io", Path: "/_home"})
}

func (s *LinkTestSuite) checkCallback(providerID string, state string, expectedURL url.URL) string {
	token := uuid.NewV4().String()
	linkServiceWithDummyProviderFactory := NewLinkServiceWithFactory(s.Configuration, gormapplication.NewGormDB(s.DB), &DummyProviderFactory{token})
	callbackLocation, err := linkServiceWithDummyProviderFactory.Callback(context.Background(), s.requestData, state, uuid.NewV4().String())
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
	var tokens []provider.ExternalToken
	err = application.Transactional(s.application, func(appl application.Application) error {
		tokens, err = appl.ExternalTokens().LoadByProviderIDAndIdentityID(context.Background(), id, s.testIdentity.ID)
		return err
	})
	require.Nil(s.T(), err)
	require.Equal(s.T(), 1, len(tokens))
	require.Equal(s.T(), expectedToken, tokens[0].Token)
}

type DummyProviderFactory struct {
	token string
}

func (factory *DummyProviderFactory) NewOauthProvider(ctx context.Context, req *goa.RequestData, forResource string) (ProviderConfig, error) {
	if forResource == "https://github.com/org/repo" {
		return &DummyProvider{factory: factory, id: gitHubProviderID, url: forResource}, nil
	}
	if forResource == "https://api.starter-us-east-2.openshift.com" {
		return &DummyProvider{factory: factory, id: osoStarterEast2ProviderID, url: forResource}, nil
	}
	return nil, errors.New("unknown provider")
}

type DummyProvider struct {
	factory *DummyProviderFactory
	id      string
	url     string
}

func (provider *DummyProvider) Exchange(ctx netcontext.Context, code string) (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: provider.factory.token}, nil
}

func (provider *DummyProvider) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return fmt.Sprintf("%s/oauth/authorize?state=%s", provider.url, state)
}

func (provider *DummyProvider) ID() uuid.UUID {
	id, _ := uuid.FromString(provider.id)
	return id
}

func (provider *DummyProvider) Scopes() string {
	return ""
}

func (provider *DummyProvider) TypeName() string {
	return "DummyProvider"
}
