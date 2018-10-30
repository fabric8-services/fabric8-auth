package test

import (
	"context"
	"errors"

	"github.com/fabric8-services/fabric8-auth/application/factory/wrapper"
	svc "github.com/fabric8-services/fabric8-auth/application/service"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/authentication/provider"
	"github.com/fabric8-services/fabric8-auth/cluster"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/satori/go.uuid"
	netcontext "golang.org/x/net/context"
	"golang.org/x/oauth2"
)

//----------------------------------------------------------------------------------------------------------------------
//
// Dummy Identity Provider
//
//----------------------------------------------------------------------------------------------------------------------

type dummyIdentityProviderFactory interface {
	setIdentityProvider(provider provider.IdentityProvider)
}

type dummyIdentityProviderFactoryImpl struct {
	wrapper.BaseFactoryWrapper
	provider provider.IdentityProvider
}

// verify that dummyIdentityProviderFactoryImpl implements all required interfaces
var _ dummyIdentityProviderFactory = &dummyIdentityProviderFactoryImpl{}
var _ svc.IdentityProviderFactory = &dummyIdentityProviderFactoryImpl{}

func ActivateDummyIdentityProviderFactory(w wrapper.Wrapper, provider provider.IdentityProvider) {
	w.WrapFactory(svc.FACTORY_TYPE_IDENTITY_PROVIDER,
		func(ctx servicecontext.ServiceContext, config *configuration.ConfigurationData) wrapper.FactoryWrapper {
			baseFactoryWrapper := wrapper.NewBaseFactoryWrapper(ctx, config)
			return &dummyIdentityProviderFactoryImpl{
				BaseFactoryWrapper: *baseFactoryWrapper,
			}
		},
		func(w wrapper.FactoryWrapper) {
			w.(dummyIdentityProviderFactory).setIdentityProvider(provider)
		})
}

func (f *dummyIdentityProviderFactoryImpl) setIdentityProvider(provider provider.IdentityProvider) {
	f.provider = provider
}

func (f *dummyIdentityProviderFactoryImpl) NewIdentityProvider(ctx context.Context, config provider.IdentityProviderConfiguration) provider.IdentityProvider {
	return f.provider
}

//----------------------------------------------------------------------------------------------------------------------
//
// Dummy Linking Provider
//
//----------------------------------------------------------------------------------------------------------------------

type dummyLinkingProviderFactory interface {
	setConfig(config *configuration.ConfigurationData)
	setToken(token string)
	setLoadProfileFail(value bool)
	setAuthCodeURL(url string)
}

type dummyLinkingProviderFactoryImpl struct {
	wrapper.BaseFactoryWrapper
	config          *configuration.ConfigurationData
	token           string
	loadProfileFail bool
	authCodeURL     string
}

// verify that dummyLinkingProviderFactoryImpl implements all required interfaces
var _ dummyLinkingProviderFactory = &dummyLinkingProviderFactoryImpl{}
var _ svc.LinkingProviderFactory = &dummyLinkingProviderFactoryImpl{}

// TODO this is getting a little out of hand, look into other ways to initialize the factory
// ActivateDummyLinkingProviderFactory can be used to create a mock linking provider factory
func ActivateDummyLinkingProviderFactory(w wrapper.Wrapper, config *configuration.ConfigurationData, token string, loadProfileFail bool, authCodeURL string) {
	w.WrapFactory(svc.FACTORY_TYPE_LINKING_PROVIDER,
		func(ctx servicecontext.ServiceContext, config *configuration.ConfigurationData) wrapper.FactoryWrapper {
			baseFactoryWrapper := wrapper.NewBaseFactoryWrapper(ctx, config)
			return &dummyLinkingProviderFactoryImpl{
				BaseFactoryWrapper: *baseFactoryWrapper,
			}
		},
		func(w wrapper.FactoryWrapper) {
			w.(dummyLinkingProviderFactory).setConfig(config)
			w.(dummyLinkingProviderFactory).setToken(token)
			w.(dummyLinkingProviderFactory).setLoadProfileFail(loadProfileFail)
			w.(dummyLinkingProviderFactory).setAuthCodeURL(authCodeURL)
		})
}

func (f *dummyLinkingProviderFactoryImpl) setConfig(config *configuration.ConfigurationData) {
	f.config = config
}

func (f *dummyLinkingProviderFactoryImpl) setToken(token string) {
	f.token = token
}

func (f *dummyLinkingProviderFactoryImpl) setLoadProfileFail(value bool) {
	f.loadProfileFail = value
}

func (f *dummyLinkingProviderFactoryImpl) setAuthCodeURL(url string) {
	f.authCodeURL = url
}

func (f *dummyLinkingProviderFactoryImpl) Configuration() *configuration.ConfigurationData {
	if f.config != nil {
		return f.config
	}
	return f.BaseFactoryWrapper.Configuration()
}

func (f *dummyLinkingProviderFactoryImpl) NewLinkingProvider(ctx context.Context, identityID uuid.UUID, authURL string, forResource string) (provider.LinkingProvider, error) {
	provider, err := f.Factory().(svc.LinkingProviderFactory).NewLinkingProvider(ctx, identityID, authURL, forResource)
	if err != nil {
		return nil, err
	}
	return &DummyLinkingProvider{factory: f, linkingProvider: provider}, nil
}

type DummyLinkingProvider struct {
	factory         *dummyLinkingProviderFactoryImpl
	linkingProvider provider.LinkingProvider
}

func (p *DummyLinkingProvider) Exchange(ctx netcontext.Context, code string) (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: p.factory.token}, nil
}

func (p *DummyLinkingProvider) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	if p.factory.authCodeURL != "" {
		return p.factory.authCodeURL
	}
	return p.linkingProvider.AuthCodeURL(state)
}

func (p *DummyLinkingProvider) ID() uuid.UUID {
	return p.linkingProvider.ID()
}

func (p *DummyLinkingProvider) Scopes() string {
	return p.linkingProvider.Scopes()
}

func (p *DummyLinkingProvider) TypeName() string {
	return p.linkingProvider.TypeName()
}

func (p *DummyLinkingProvider) URL() string {
	return p.linkingProvider.URL()
}

func (p *DummyLinkingProvider) SetRedirectURL(redirectURL string) {
	p.linkingProvider.SetRedirectURL(redirectURL)
}

func (p *DummyLinkingProvider) SetScopes(scopes []string) {
	p.linkingProvider.SetScopes(scopes)
}

func (p *DummyLinkingProvider) Profile(ctx context.Context, token oauth2.Token) (*provider.UserProfile, error) {
	if p.factory.loadProfileFail {
		return nil, errors.New("unable to load profile")
	}
	return &provider.UserProfile{
		Username: token.AccessToken + "testuser",
	}, nil
}

func (provider *DummyLinkingProvider) OSOCluster() cluster.Cluster {
	return *ClusterByURL(provider.URL())
}
