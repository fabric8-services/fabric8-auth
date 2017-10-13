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

func NewOpenShiftConfig(apiUrl string, clientID string, clientSecret string, scopes string, authURL string) *OpenShiftConfig {
	provider := &OpenShiftConfig{}
	provider.ClientID = clientID
	provider.ClientSecret = clientSecret
	provider.Endpoint = oauth2.Endpoint{
		AuthURL:  fmt.Sprintf("%s/oauth/authorize", apiUrl),
		TokenURL: fmt.Sprintf("%s/oauth/access_token", apiUrl),
	}
	provider.RedirectURL = authURL + client.CallbackTokenPath()
	provider.scopeStr = scopes
	provider.Config.Scopes = strings.Split(scopes, " ")
	provider.providerID, _ = uuid.FromString(osoStarterEast2ProviderID)
	return provider
}

func (config *OpenShiftConfig) ID() uuid.UUID {
	return config.providerID
}

func (config *OpenShiftConfig) Scopes() string {
	return config.scopeStr
}

func (config *OpenShiftConfig) TypeName() string {
	return "OpenShift"
}
