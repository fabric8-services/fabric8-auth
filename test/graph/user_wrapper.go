package graph

import (
	"fmt"

	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
)

// userWrapper represents a user domain object
type userWrapper struct {
	baseWrapper
	user     *account.User
	identity *account.Identity
}

func loadUserWrapper(g *TestGraph, identityID uuid.UUID, options ...LoadOption) userWrapper {
	w := userWrapper{baseWrapper: baseWrapper{g}}
	db := w.graph.db
	for _, opt := range options {
		db = opt(db)
	}
	var identity account.Identity
	err := db.Table(identity.TableName()).Where("id = ?", identityID).Find(&identity).Error
	require.NoError(w.graph.t, err)
	var user account.User
	err = db.Table(user.TableName()).Where("id = ?", identity.UserID).Find(&user).Error
	require.NoError(w.graph.t, err)

	w.identity = &identity
	w.user = &user
	w.identity.User = user
	return w
}

func newUserWrapper(g *TestGraph, params []interface{}) interface{} {
	w := userWrapper{baseWrapper: baseWrapper{g}}
	id := uuid.NewV4()
	fullname := fmt.Sprintf("TestUser-%s", id)
	emailPrivate := false
	for _, param := range params {
		switch p := param.(type) {
		case bool:
			emailPrivate = p
		case string:
			fullname = p
		}
	}
	w.user = &account.User{
		ID:           id,
		Active:       true,
		Email:        fmt.Sprintf("TestUser-%s@test.com", id),
		EmailPrivate: emailPrivate,
		FullName:     fullname,
		Cluster:      fmt.Sprintf("TestCluster-%s", id),
		FeatureLevel: "released",
	}

	err := g.app.Users().Create(g.ctx, w.user)
	require.NoError(g.t, err)

	w.identity = &account.Identity{
		Username:     fmt.Sprintf("TestUserIdentity-%s", id),
		ProviderType: account.DefaultIDP,
		User:         *w.user,
		UserID: account.NullUUID{
			UUID:  w.user.ID,
			Valid: true},
	}

	err = g.app.Identities().Create(g.ctx, w.identity)
	require.NoError(g.t, err)

	return &w
}

func (w *userWrapper) User() *account.User {
	return w.user
}

func (w *userWrapper) Identity() *account.Identity {
	return w.identity
}

func (w *userWrapper) IdentityID() uuid.UUID {
	return w.identity.ID
}

func (w *userWrapper) Deprovision() {
	w.user.Banned = true
	err := w.graph.app.Users().Save(w.graph.ctx, w.user)
	require.NoError(w.graph.t, err)
}
