package test

import (
	"context"
	svc "github.com/fabric8-services/fabric8-auth/application/service"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/application/service/factory"
	"github.com/fabric8-services/fabric8-auth/authentication/provider"
	"github.com/fabric8-services/fabric8-auth/cluster"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	netcontext "golang.org/x/net/context"
	"golang.org/x/oauth2"
)

type dummyLinkingProviderFactory interface {
	setConfig(config *configuration.ConfigurationData)
	setToken(token string)
	setLoadProfileFail(value bool)
}

type dummyLinkingProviderFactoryImpl struct {
	factory.BaseFactoryWrapper
	config          *configuration.ConfigurationData
	Token           string
	LoadProfileFail bool
}

func NewDummyLinkingProviderFactory(testsuite *gormtestsupport.DBTestSuite, config *configuration.ConfigurationData, token string, loadProfileFail bool) {
	testsuite.WrapFactory(svc.FACTORY_TYPE_LINKING_PROVIDER, dummyLinkingProviderFactoryConstructor, func(wrapper factory.FactoryWrapper) {
		wrapper.(dummyLinkingProviderFactory).setConfig(config)
		wrapper.(dummyLinkingProviderFactory).setToken(token)
		wrapper.(dummyLinkingProviderFactory).setLoadProfileFail(loadProfileFail)
	})
}

func dummyLinkingProviderFactoryConstructor(ctx servicecontext.ServiceContext, config *configuration.ConfigurationData) factory.FactoryWrapper {
	baseFactoryWrapper := factory.NewBaseFactoryWrapper(ctx, config)
	return &dummyLinkingProviderFactoryImpl{
		BaseFactoryWrapper: *baseFactoryWrapper,
	}
}

func (f *dummyLinkingProviderFactoryImpl) setConfig(config *configuration.ConfigurationData) {
	f.config = config
}

func (f *dummyLinkingProviderFactoryImpl) setToken(token string) {
	f.Token = token
}

func (f *dummyLinkingProviderFactoryImpl) Configuration() *configuration.ConfigurationData {
	return f.config
}

func (f *dummyLinkingProviderFactoryImpl) setLoadProfileFail(value bool) {
	f.LoadProfileFail = value
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

func (p *DummyProvider) Profile(ctx context.Context, token oauth2.Token) (*provider.UserProfile, error) {
	return &provider.UserProfile{
		Username: token.AccessToken + "testuser",
	}, nil
}

func (provider *DummyProvider) OSOCluster() cluster.Cluster {
	return *ClusterByURL(provider.URL())
}
