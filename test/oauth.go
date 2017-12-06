package test

import (
	"context"
	"errors"
	"fmt"

	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/token/link"
	"github.com/fabric8-services/fabric8-auth/token/oauth"

	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	netcontext "golang.org/x/net/context"
	"golang.org/x/oauth2"
	"strings"
)

type DummyProviderFactory struct {
	Token           string
	Config          *configuration.ConfigurationData
	LoadProfileFail bool
}

func (factory *DummyProviderFactory) NewOauthProvider(ctx context.Context, req *goa.RequestData, forResource string) (link.ProviderConfig, error) {
	if strings.HasPrefix(forResource, "https://github.com") {
		return &DummyProvider{factory: factory, id: link.GitHubProviderID, url: forResource, name: "github"}, nil
	}
	if strings.HasPrefix(forResource, "https://api.starter-us-east-2.openshift.com") {
		cluster := factory.Config.GetOSOClusters()["https://api.starter-us-east-2.openshift.com"]
		return &DummyProvider{factory: factory, id: cluster.TokenProviderID, url: forResource, name: "openshift-v3"}, nil
	}
	return nil, errors.New("unknown provider")
}

type DummyProvider struct {
	factory *DummyProviderFactory
	id      string
	url     string
	name    string
}

func (provider *DummyProvider) Exchange(ctx netcontext.Context, code string) (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: provider.factory.Token}, nil
}

func (provider *DummyProvider) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return fmt.Sprintf("%s/oauth/authorize?state=%s", provider.url, state)
}

func (provider *DummyProvider) ID() uuid.UUID {
	id, _ := uuid.FromString(provider.id)
	return id
}

func (provider *DummyProvider) Scopes() string {
	return "testscope"
}

func (provider *DummyProvider) TypeName() string {
	return provider.name
}

func (provider *DummyProvider) Profile(ctx context.Context, token oauth2.Token) (*oauth.UserProfile, error) {
	if provider.factory.LoadProfileFail {
		return nil, errors.New("unable to load profile")
	}
	return &oauth.UserProfile{
		Username: token.AccessToken + "testuser",
	}, nil
}
