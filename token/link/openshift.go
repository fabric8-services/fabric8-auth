package link

import (
	"strings"

	"github.com/fabric8-services/fabric8-auth/client"

	"fmt"
	"github.com/satori/go.uuid"
	"golang.org/x/oauth2"
)

const (
	osoStarterEast2ProviderID = "f867ac10-5e05-4359-a0c6-b855ece59090" // Do not change! This ID is used as provider ID in the external token table
)

type OpenShiftConfig struct {
	oauth2.Config
	providerID uuid.UUID
	scopeStr   string
}

func NewOpenShiftConfig(clientHost string, clientID string, clientSecret string, scopes string, authURL string) *GitHubConfig {
	provider := &GitHubConfig{}
	provider.ClientID = clientID
	provider.ClientSecret = clientSecret
	provider.Endpoint = oauth2.Endpoint{
		AuthURL:  fmt.Sprintf("https://api.%s/oauth/authorize", clientHost),
		TokenURL: fmt.Sprintf("https://api.%s/oauth/access_token", clientHost),
	}
	provider.RedirectURL = authURL + client.CallbackTokenPath()
	provider.scopeStr = scopes
	provider.Config.Scopes = strings.Split(scopes, " ")
	provider.providerID, _ = uuid.FromString(osoStarterEast2ProviderID)
	return provider
}

func (config *OpenShiftConfig) ID() uuid.UUID {
	return config.ID()
}

func (config *OpenShiftConfig) Scopes() string {
	return config.scopeStr
}
