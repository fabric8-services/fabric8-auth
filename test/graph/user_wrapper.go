package graph

import (
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
)

// userWrapper represents a user domain object
type userWrapper struct {
	baseWrapper
	user     *account.User
	identity *account.Identity
}

func newUserWrapper(g *TestGraph, params []interface{}) userWrapper {
	w := userWrapper{baseWrapper: baseWrapper{g}}

	w.user = &account.User{
		ID:       uuid.NewV4(),
		Email:    uuid.NewV4().String() + "@random.com",
		FullName: "TestUser-" + uuid.NewV4().String(),
		Cluster:  "TestCluster-" + uuid.NewV4().String(),
	}

	err := g.app.Users().Create(g.ctx, w.user)
	require.NoError(g.t, err)

	w.identity = &account.Identity{
		Username:     "TestUserIdentity-" + uuid.NewV4().String(),
		ProviderType: account.KeycloakIDP,
		User:         *w.user,
		UserID:       account.NullUUID{w.user.ID, true},
	}

	err = g.app.Identities().Create(g.ctx, w.identity)
	require.NoError(g.t, err)

	return w
}

func (w *userWrapper) User() *account.User {
	return w.user
}

func (w *userWrapper) Identity() *account.Identity {
	return w.identity
}
