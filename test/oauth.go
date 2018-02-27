package test

import (
	"context"
	"errors"

	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/token/link"
	"github.com/fabric8-services/fabric8-auth/token/oauth"

	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	netcontext "golang.org/x/net/context"
	"golang.org/x/oauth2"
)

type DummyProviderFactory struct {
	Token           string
	Config          *configuration.ConfigurationData
	LoadProfileFail bool
	DB              application.DB
}

func (factory *DummyProviderFactory) NewOauthProvider(ctx context.Context, identityID uuid.UUID, req *goa.RequestData, forResource string) (link.ProviderConfig, error) {
	providerFactory := link.NewOauthProviderFactory(factory.Config, factory.DB)
	provider, err := providerFactory.NewOauthProvider(ctx, identityID, req, forResource)
	if err != nil {
		return nil, err
	}
	return &DummyProvider{factory: factory, providerConfig: provider}, nil
}

type DummyProvider struct {
	factory        *DummyProviderFactory
	providerConfig link.ProviderConfig
}

func (provider *DummyProvider) Exchange(ctx netcontext.Context, code string) (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: provider.factory.Token}, nil
}

func (provider *DummyProvider) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return provider.providerConfig.AuthCodeURL(state)
}

func (provider *DummyProvider) ID() uuid.UUID {
	return provider.providerConfig.ID()
}

func (provider *DummyProvider) Scopes() string {
	return provider.providerConfig.Scopes()
}

func (provider *DummyProvider) TypeName() string {
	return provider.providerConfig.TypeName()
}

func (provider *DummyProvider) URL() string {
	return provider.providerConfig.URL()
}

func (provider *DummyProvider) Profile(ctx context.Context, token oauth2.Token) (*oauth.UserProfile, error) {
	if provider.factory.LoadProfileFail {
		return nil, errors.New("unable to load profile")
	}
	return &oauth.UserProfile{
		Username: token.AccessToken + "testuser",
	}, nil
}

func (provider *DummyProvider) OSOCluster() configuration.OSOCluster {
	return *provider.factory.Config.GetOSOClusterByURL(provider.URL())
}
