package token

import (
	"testing"

	"fmt"

	config "github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/stretchr/testify/require"
)

var (
	c *config.ConfigurationData
)

func init() {
	var err error
	c, err = config.GetConfigurationData()
	if err != nil {
		panic(fmt.Errorf("failed to setup the configuration: %s", err.Error()))
	}
}

func TestKeycloakTokensLoaded(t *testing.T) {
	resource.Require(t, resource.Remote)
	m, err := NewManager(c)
	require.Nil(t, err)
	require.NotNil(t, m)
	tm, ok := m.(*tokenManager)
	require.True(t, ok)

	minKeyNumber := 2 // At least one service account key and one Keycloak key
	_, serviceAccountKid := c.GetServiceAccountPrivateKey()
	require.NotEqual(t, "", serviceAccountKid)
	require.NotNil(t, m.PublicKey(serviceAccountKid))

	_, dServiceAccountKid := c.GetDeprecatedServiceAccountPrivateKey()
	if dServiceAccountKid != "" {
		minKeyNumber++
		require.NotNil(t, m.PublicKey(dServiceAccountKid))
	}
	require.True(t, len(tm.PublicKeys()) >= minKeyNumber)

	require.Equal(t, len(tm.publicKeys), len(m.PublicKeys()))
	require.Equal(t, len(tm.publicKeys), len(tm.publicKeysMap))
	for i, k := range tm.publicKeys {
		require.NotEqual(t, "", k.KeyID)
		require.NotNil(t, m.PublicKey(k.KeyID))
		require.Equal(t, m.PublicKeys()[i], k.Key)
	}

	jwKeys := m.JsonWebKeys()
	require.NotEmpty(t, jwKeys.Keys)

	pemKeys := m.PemKeys()
	require.NotEmpty(t, pemKeys.Keys)
}
