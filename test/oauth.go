package test

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application/factory/wrapper"
	svc "github.com/fabric8-services/fabric8-auth/application/service"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/authentication/provider"
	"github.com/fabric8-services/fabric8-auth/cluster"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/goadesign/goa"
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
}

type dummyLinkingProviderFactoryImpl struct {
	wrapper.BaseFactoryWrapper
	config *configuration.ConfigurationData
	Token  string
}

// ActivateDummyLinkingProviderFactory can be used to create a mock linking provider factory
func ActivateDummyLinkingProviderFactory(w wrapper.Wrapper, config *configuration.ConfigurationData, token string) {
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
		})
}

func (f *dummyLinkingProviderFactoryImpl) setConfig(config *configuration.ConfigurationData) {
	f.config = config
}

func (f *dummyLinkingProviderFactoryImpl) setToken(token string) {
	f.Token = token
}

func (f *dummyLinkingProviderFactoryImpl) Configuration() *configuration.ConfigurationData {
	if f.config != nil {
		return f.config
	}
	return f.BaseFactoryWrapper.Configuration()
}

func (f *dummyLinkingProviderFactoryImpl) NewLinkingProvider(ctx context.Context, identityID uuid.UUID, req *goa.RequestData, forResource string) (provider.LinkingProvider, error) {
	provider, err := f.Factory().(svc.LinkingProviderFactory).NewLinkingProvider(ctx, identityID, req, forResource)
	if err != nil {
		return nil, err
	}
	return &DummyProvider{factory: f, linkingProvider: provider}, nil
}

type DummyProvider struct {
	factory         *dummyLinkingProviderFactoryImpl
	linkingProvider provider.LinkingProvider
}

func (p *DummyProvider) Exchange(ctx netcontext.Context, code string) (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: p.factory.Token}, nil
}

func (p *DummyProvider) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return p.linkingProvider.AuthCodeURL(state)
}

func (p *DummyProvider) ID() uuid.UUID {
	return p.linkingProvider.ID()
}

func (p *DummyProvider) Scopes() string {
	return p.linkingProvider.Scopes()
}

func (p *DummyProvider) TypeName() string {
	return p.linkingProvider.TypeName()
}

func (p *DummyProvider) URL() string {
	return p.linkingProvider.URL()
}

func (p *DummyProvider) SetRedirectURL(redirectURL string) {
	p.linkingProvider.SetRedirectURL(redirectURL)
}

func (p *DummyProvider) SetScopes(scopes []string) {
	p.linkingProvider.SetScopes(scopes)
}

func (p *DummyProvider) Profile(ctx context.Context, token oauth2.Token) (*provider.UserProfile, error) {
	return &provider.UserProfile{
		Username: token.AccessToken + "testuser",
	}, nil
}

func (provider *DummyProvider) OSOCluster() cluster.Cluster {
	return *ClusterByURL(provider.URL())
}
