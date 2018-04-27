package graph

import (
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
)

// identityWrapper represents a user domain object
type identityWrapper struct {
	baseWrapper
	identity *account.Identity
}

func loadIdentityWrapper(g *TestGraph, identityID uuid.UUID) identityWrapper {
	w := identityWrapper{baseWrapper: baseWrapper{g}}

	var native account.Identity
	err := w.graph.db.Table("identities").Where("ID = ?", identityID).Find(&native).Error
	require.NoError(w.graph.t, err)

	w.identity = &native

	return w
}

func newIdentityWrapper(g *TestGraph, params []interface{}) identityWrapper {
	w := identityWrapper{baseWrapper: baseWrapper{g}}

	w.identity = &account.Identity{
		Username:     "TestUserIdentity-" + uuid.NewV4().String(),
		ProviderType: account.KeycloakIDP,
	}

	err := g.app.Identities().Create(g.ctx, w.identity)
	require.NoError(g.t, err)

	return w
}

func (w *identityWrapper) Identity() *account.Identity {
	return w.identity
}
