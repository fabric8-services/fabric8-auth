package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pkg/errors"

	"github.com/fabric8-services/fabric8-auth/rest"

	"github.com/fabric8-services/fabric8-auth/client"
	"github.com/fabric8-services/fabric8-auth/cluster"

	"github.com/satori/go.uuid"
	"golang.org/x/oauth2"
)

const (
	OpenShiftProviderAlias = "openshift"
)

// OpenShiftIdentityProvider represents an OpenShift Identity Provider
type OpenShiftIdentityProvider interface {
	LinkingProvider
	OSOCluster() cluster.Cluster
}

type OpenShiftIdentityProviderImpl struct {
	DefaultIdentityProvider
	Cluster cluster.Cluster
}

type openshiftUser struct {
	Metadata metadata `json:"metadata"`
}

type metadata struct {
	Name string `json:"name"`
}

func NewOpenShiftIdentityProvider(cluster cluster.Cluster, authURL string) (OpenShiftIdentityProvider, error) {
	provider := &OpenShiftIdentityProviderImpl{}
	provider.Cluster = cluster
	provider.ClientID = cluster.AuthClientID
	provider.ClientSecret = cluster.AuthClientSecret
	provider.Endpoint = oauth2.Endpoint{
		AuthURL:  fmt.Sprintf("%soauth/authorize", rest.AddTrailingSlashToURL(cluster.APIURL)),
		TokenURL: fmt.Sprintf("%soauth/token", rest.AddTrailingSlashToURL(cluster.APIURL)),
	}
	provider.RedirectURL = authURL + client.LinkCallbackTokenPath()
	provider.ScopeStr = cluster.AuthClientDefaultScope
	provider.Config.Scopes = strings.Split(cluster.AuthClientDefaultScope, " ")
	prID, err := uuid.FromString(cluster.TokenProviderID)
	if err != nil {
		return nil, errors.Wrap(err, "unable to convert cluster TokenProviderID to UUID")
	}
	provider.ProviderID = prID
	provider.ProfileURL = fmt.Sprintf("%soapi/v1/users/~", rest.AddTrailingSlashToURL(cluster.APIURL))
	return provider, nil
}

func (provider *OpenShiftIdentityProviderImpl) ID() uuid.UUID {
	return provider.ProviderID
}

func (provider *OpenShiftIdentityProviderImpl) Scopes() string {
	return provider.ScopeStr
}

func (provider *OpenShiftIdentityProviderImpl) TypeName() string {
	return "openshift-v3"
}

func (provider *OpenShiftIdentityProviderImpl) OSOCluster() cluster.Cluster {
	return provider.Cluster
}

func (provider *OpenShiftIdentityProviderImpl) URL() string {
	return provider.Cluster.APIURL
}

// Profile fetches a user profile from the Identity Provider
func (provider *OpenShiftIdentityProviderImpl) Profile(ctx context.Context, token oauth2.Token) (*UserProfile, error) {
	body, err := provider.UserProfilePayload(ctx, token)
	if err != nil {
		return nil, err
	}
	var u openshiftUser
	err = json.Unmarshal(body, &u)
	if err != nil {
		return nil, err
	}
	userProfile := &UserProfile{
		Username: u.Metadata.Name,
	}
	return userProfile, nil
}
