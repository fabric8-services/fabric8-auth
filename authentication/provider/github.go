package provider

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/fabric8-services/fabric8-auth/client"

	"github.com/satori/go.uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

const (
	GitHubProviderID    = "2f6b7176-8f4b-4204-962d-606033275397" // Do not change! This ID is used as provider ID in the external token table
	GitHubProviderAlias = "github"
)

type GitHubIdentityProvider struct {
	DefaultIdentityProvider
}

type gitHubUser struct {
	Login string `json:"login"`
}

func NewGitHubIdentityProvider(clientID string, clientSecret string, scopes string, authURL string) *GitHubIdentityProvider {
	provider := &GitHubIdentityProvider{}
	provider.ClientID = clientID
	provider.ClientSecret = clientSecret
	provider.Endpoint = github.Endpoint
	provider.RedirectURL = authURL + client.LinkCallbackTokenPath()
	provider.ScopeStr = scopes
	provider.Config.Scopes = strings.Split(scopes, " ")
	provider.ProviderID, _ = uuid.FromString(GitHubProviderID)
	provider.ProfileURL = "https://api.github.com/user"
	return provider
}

func (provider *GitHubIdentityProvider) ID() uuid.UUID {
	return provider.ProviderID
}

func (provider *GitHubIdentityProvider) Scopes() string {
	return provider.ScopeStr
}

func (provider *GitHubIdentityProvider) TypeName() string {
	return "github"
}

func (provider *GitHubIdentityProvider) URL() string {
	return "https://github.com"
}

// Profile fetches a user profile from the Identity Provider
func (provider *GitHubIdentityProvider) Profile(ctx context.Context, token oauth2.Token) (*UserProfile, error) {
	body, err := provider.UserProfilePayload(ctx, token)
	if err != nil {
		return nil, err
	}
	var u gitHubUser
	err = json.Unmarshal(body, &u)
	if err != nil {
		return nil, err
	}
	userProfile := &UserProfile{
		Username: u.Login,
	}
	return userProfile, nil
}
