package link

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fabric8-services/fabric8-auth/client"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/token/oauth"

	"github.com/satori/go.uuid"
	"golang.org/x/oauth2"
)

const (
	OpenShiftProviderAlias = "openshift"
)

// OpenShiftIdentityProviderConfig represents an OpenShift Identity Provider
type OpenShiftIdentityProviderConfig interface {
	oauth.IdentityProvider
	OSOCluster() configuration.OSOCluster
}

type OpenShiftIdentityProvider struct {
	oauth.OauthIdentityProvider
	Cluster configuration.OSOCluster
}

type openshiftUser struct {
	Metadata metadata `json:"metadata"`
}

type metadata struct {
	Name string `json:"name"`
}

func NewOpenShiftIdentityProvider(cluster configuration.OSOCluster, authURL string) (*OpenShiftIdentityProvider, error) {
	provider := &OpenShiftIdentityProvider{}
	provider.Cluster = cluster
	provider.ClientID = cluster.AuthClientID
	provider.ClientSecret = cluster.AuthClientSecret
	provider.Endpoint = oauth2.Endpoint{
		AuthURL:  fmt.Sprintf("%s/oauth/authorize", cluster.APIURL),
		TokenURL: fmt.Sprintf("%s/oauth/token", cluster.APIURL),
	}
	provider.RedirectURL = authURL + client.CallbackTokenPath()
	provider.ScopeStr = cluster.AuthClientDefaultScope
	provider.Config.Scopes = strings.Split(cluster.AuthClientDefaultScope, " ")
	prID, err := uuid.FromString(cluster.TokenProviderID)
	if err != nil {
		return nil, err
	}
	provider.ProviderID = prID
	provider.ProfileURL = fmt.Sprintf("%s/oapi/v1/users/~", cluster.APIURL)
	return provider, nil
}

func (provider *OpenShiftIdentityProvider) ID() uuid.UUID {
	return provider.ProviderID
}

func (provider *OpenShiftIdentityProvider) Scopes() string {
	return provider.ScopeStr
}

func (provider *OpenShiftIdentityProvider) TypeName() string {
	return "openshift-v3"
}

func (provider *OpenShiftIdentityProvider) OSOCluster() configuration.OSOCluster {
	return provider.Cluster
}

func (provider *OpenShiftIdentityProvider) URL() string {
	return provider.Cluster.APIURL
}

// Profile fetches a user profile from the Identity Provider
func (provider *OpenShiftIdentityProvider) Profile(ctx context.Context, token oauth2.Token) (*oauth.UserProfile, error) {
	body, err := provider.UserProfilePayload(ctx, token)
	if err != nil {
		return nil, err
	}
	var u openshiftUser
	err = json.Unmarshal(body, &u)
	userProfile := &oauth.UserProfile{
		Username: u.Metadata.Name,
	}
	return userProfile, nil
}
