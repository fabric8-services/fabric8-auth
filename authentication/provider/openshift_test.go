package provider_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/authentication/provider"
	"github.com/fabric8-services/fabric8-auth/cluster"
	"github.com/fabric8-services/fabric8-auth/resource"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenShiftProviderID(t *testing.T) {
	resource.Require(t, resource.UnitTest)

	prID := uuid.NewV4()
	scope := uuid.NewV4().String()
	id := uuid.NewV4().String()
	secret := uuid.NewV4().String()
	cluster := cluster.Cluster{
		APIURL:                 "https://api.starter-us-east-2.openshift.com",
		TokenProviderID:        prID.String(),
		AuthClientDefaultScope: scope,
		AuthClientID:           id,
		AuthClientSecret:       secret,
	}
	p, err := provider.NewOpenShiftIdentityProvider(cluster, "https://test-auth")
	require.NoError(t, err)
	provider := p.(*provider.OpenShiftIdentityProviderImpl)
	assert.Equal(t, provider.Cluster, cluster)
	assert.Equal(t, provider.ProfileURL, "https://api.starter-us-east-2.openshift.com/oapi/v1/users/~")
	assert.Equal(t, provider.ProviderID, prID)
	assert.Equal(t, provider.ScopeStr, scope)
	assert.Equal(t, provider.ClientID, id)
	assert.Equal(t, provider.Cluster.AuthClientSecret, secret)
	assert.Equal(t, provider.RedirectURL, "https://test-auth/api/token/link/callback")
}
