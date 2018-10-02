package link

import (
	"testing"

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
	p, err := NewOpenShiftIdentityProvider(cluster, "https://test-auth")
	require.NoError(t, err)
	assert.Equal(t, p.Cluster, cluster)
	assert.Equal(t, p.ProfileURL, "https://api.starter-us-east-2.openshift.com/oapi/v1/users/~")
	assert.Equal(t, p.ProviderID, prID)
	assert.Equal(t, p.ScopeStr, scope)
	assert.Equal(t, p.ClientID, id)
	assert.Equal(t, p.Cluster.AuthClientSecret, secret)
	assert.Equal(t, p.RedirectURL, "https://test-auth/api/token/link/callback")
}
