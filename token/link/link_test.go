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
	"github.com/fabric8-services/fabric8-auth/gormsupport/cleaner"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/fabric8-services/fabric8-auth/test"
	"github.com/fabric8-services/fabric8-auth/token/provider"

	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	netcontext "golang.org/x/net/context"
	"golang.org/x/oauth2"
	"os"
)

type LinkTestSuite struct {
	gormtestsupport.DBTestSuite
	application  application.DB
	linkService  LinkOAuthService
	testIdentity account.Identity
	requestData  *goa.RequestData
	clean        func()
}

func TestRunLinkTestSuite(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &LinkTestSuite{DBTestSuite: gormtestsupport.NewDBTestSuite("")})
}

func (s *LinkTestSuite) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	s.application = gormapplication.NewGormDB(s.DB)
	s.linkService = NewLinkService(s.Configuration, s.application)
	var err error
	s.testIdentity, err = test.CreateTestIdentity(s.DB, "TestLinkSuite user", "test provider")
	require.Nil(s.T(), err)
	s.requestData = &goa.RequestData{Request: &http.Request{
		URL: &url.URL{Scheme: "https", Host: "auth.openshift.io"},
	}}
}

func (s *LinkTestSuite) SetupTest() {
	s.clean = cleaner.DeleteCreatedEntities(s.DB)
}

func (s *LinkTestSuite) TearDownTest() {
	s.clean()
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
	require.Contains(s.T(), location, "https://github.com/login/oauth/authorize")
	require.NotEmpty(s.T(), s.stateParam(location))
}

func (s *LinkTestSuite) TestOSOProviderRedirectsToAuthorize() {
	location, err := s.linkService.ProviderLocation(context.Background(), s.requestData, s.testIdentity.ID.String(), "https://api."+s.Configuration.GetOpenShiftClientHost(), "https://openshift.io/home")
	require.Nil(s.T(), err)
	require.Contains(s.T(), location, fmt.Sprintf("https://api.%s/oauth/authorize", s.Configuration.GetOpenShiftClientHost()))
	require.NotEmpty(s.T(), s.stateParam(location))
}

func (s *LinkTestSuite) stateParam(location string) string {
	locationURL, err := url.Parse(location)
	require.Nil(s.T(), err)
	allQueryParameters := locationURL.Query()
	require.NotNil(s.T(), allQueryParameters)
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

	id, err := uuid.FromString(gitHubProviderID)
	require.Nil(s.T(), err)
	var tokens []provider.ExternalToken
	err = application.Transactional(s.application, func(appl application.Application) error {
		tokens, err = appl.ExternalTokens().LoadByProviderIDAndIdentityID(context.Background(), id, s.testIdentity.ID)
		return err
	})
	require.Nil(s.T(), err)
	require.Equal(s.T(), 1, len(tokens))
	require.Equal(s.T(), token, tokens[0].Token)
}

type DummyProviderFactory struct {
	token string
}

func (factory *DummyProviderFactory) NewOauthProvider(ctx context.Context, req *goa.RequestData, config LinkConfig, forResource string) (ProviderConfig, error) {
	return &DummyProvider{factory}, nil
}

type DummyProvider struct {
	factory *DummyProviderFactory
}

func (provider *DummyProvider) Exchange(ctx netcontext.Context, code string) (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: provider.factory.token}, nil
}

func (provider *DummyProvider) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return ""
}

func (provider *DummyProvider) ID() uuid.UUID {
	id, _ := uuid.FromString(gitHubProviderID)
	return id
}

func (provider *DummyProvider) Scopes() string {
	return ""
}
