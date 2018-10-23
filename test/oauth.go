package test

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/authentication/provider"
	"github.com/fabric8-services/fabric8-auth/cluster"
	"github.com/fabric8-services/fabric8-auth/configuration"

	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	netcontext "golang.org/x/net/context"
	"golang.org/x/oauth2"
)

type DummyProviderFactory struct {
	Token           string
	Config          *configuration.ConfigurationData
	LoadProfileFail bool
	App             application.Application
}

func (factory *DummyProviderFactory) NewOAuthProvider(ctx context.Context, identityID uuid.UUID, req *goa.RequestData, forResource string) (provider.LinkingProvider, error) {
	providerFactory := provider.NewOAuthProviderFactory(factory.Config, factory.App)
	provider, err := providerFactory.NewOauthProvider(ctx, identityID, req, forResource)
	if err != nil {
		return nil, err
	}
	return &DummyProvider{factory: factory, linkingProvider: linkingProvider}, nil
}

type DummyProvider struct {
	factory         *DummyProviderFactory
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
