package link

import (
	"strings"

	"github.com/fabric8-services/fabric8-auth/client"

	"fmt"

	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/satori/go.uuid"
	"golang.org/x/oauth2"
)

type OpenShiftConfig struct {
	oauth2.Config
	providerID uuid.UUID
	scopeStr   string
}

func NewOpenShiftConfig(cluster configuration.OSOCluster, authURL string) (*OpenShiftConfig, error) {
	provider := &OpenShiftConfig{}
	provider.ClientID = cluster.AuthClientID
	provider.ClientSecret = cluster.AuthClientSecret
	provider.Endpoint = oauth2.Endpoint{
		AuthURL:  fmt.Sprintf("%s/oauth/authorize", cluster.URL),
		TokenURL: fmt.Sprintf("%s/oauth/access_token", cluster.URL),
	}
	provider.RedirectURL = authURL + client.CallbackTokenPath()
	provider.scopeStr = cluster.AuthClientDefaultScope
	provider.Config.Scopes = strings.Split(cluster.AuthClientDefaultScope, " ")
	prID, err := uuid.FromString(cluster.TokenProviderID)
	if err != nil {
		return nil, err
	}
	provider.providerID = prID
	return provider, nil
}

func (config *OpenShiftConfig) ID() uuid.UUID {
	return config.providerID
}

func (config *OpenShiftConfig) Scopes() string {
	return config.scopeStr
}

func (config *OpenShiftConfig) TypeName() string {
	return "openshift-v3"
}
