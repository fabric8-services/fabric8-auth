package link

import (
	"strings"

	"github.com/fabric8-services/fabric8-auth/client"

	"github.com/satori/go.uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

const (
	gitHubProviderID = "2f6b7176-8f4b-4204-962d-606033275397" // Do not change! This ID is used as provider ID in the external token table
)

type GitHubConfig struct {
	oauth2.Config
	providerID uuid.UUID
	scopeStr   string
}

func NewGitHubConfig(clientID string, clientSecret string, scopes string, authURL string) *GitHubConfig {
	provider := &GitHubConfig{}
	provider.ClientID = clientID
	provider.ClientSecret = clientSecret
	provider.Endpoint = github.Endpoint
	provider.RedirectURL = authURL + client.CallbackTokenPath()
	provider.scopeStr = scopes
	provider.Config.Scopes = strings.Split(scopes, " ")
	provider.providerID, _ = uuid.FromString(gitHubProviderID)
	return provider
}

func (config *GitHubConfig) ID() uuid.UUID {
	return config.providerID
}

func (config *GitHubConfig) Scopes() string {
	return config.scopeStr
}

func (config *GitHubConfig) TypeName() string {
	return "GitHub"
}
