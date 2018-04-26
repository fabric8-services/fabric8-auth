package graph

import (
	"database/sql"
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/authorization"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
)

// teamWrapper represents a space resource domain object
type teamWrapper struct {
	baseWrapper
	identity *account.Identity
}

func loadTeamWrapper(g *TestGraph, teamID uuid.UUID) teamWrapper {
	w := teamWrapper{baseWrapper: baseWrapper{g}}

	var native account.Identity
	err := w.graph.db.Table("identities").Preload("IdentityResource").Where("ID = ?", teamID).Find(&native).Error
	require.NoError(w.graph.t, err)

	w.identity = &native

	return w
}

func newTeamWrapper(g *TestGraph, params ...interface{}) teamWrapper {
	w := teamWrapper{baseWrapper: baseWrapper{g}}

	var teamName *string
	var space *resource.Resource

	for i, _ := range params {
		switch t := params[i].(type) {
		case string:
			teamName = &t
		case spaceWrapper:
			space = t.Resource()
		}
	}

	resourceType, err := g.app.ResourceTypeRepository().Lookup(g.ctx, authorization.IdentityResourceTypeTeam)
	require.NoError(g.t, err)

	if teamName == nil {
		nm := "Team-" + uuid.NewV4().String()
		teamName = &nm
	}

	res := &resource.Resource{
		Name:             *teamName,
		ResourceType:     *resourceType,
		ResourceTypeID:   resourceType.ResourceTypeID,
		ParentResourceID: &space.ResourceID,
	}

	err = g.app.ResourceRepository().Create(g.ctx, res)
	require.NoError(g.t, err)

	w.identity = &account.Identity{
		ProviderType:       account.KeycloakIDP,
		IdentityResourceID: sql.NullString{String: res.ResourceID, Valid: true},
		IdentityResource:   *res,
	}

	return w
}

func (w *teamWrapper) AddMember(user *userWrapper) *teamWrapper {
	err := w.graph.db.Exec("INSERT INTO membership (member_id, member_of) VALUES (?, ?)", user.Identity().ID, w.identity.ID).Error
	require.NoError(w.graph.t, err)
	return w
}

func (w *teamWrapper) addUserRole(user *userWrapper, roleName string) *teamWrapper {
	r, err := w.graph.app.RoleRepository().Lookup(w.graph.ctx, roleName, authorization.IdentityResourceTypeTeam)
	require.NoError(w.graph.t, err)

	identityRole := &role.IdentityRole{
		ResourceID: w.identity.IdentityResourceID.String,
		IdentityID: user.Identity().ID,
		RoleID:     r.RoleID,
	}

	err = w.graph.app.IdentityRoleRepository().Create(w.graph.ctx, identityRole)
	require.NoError(w.graph.t, err)
	return w
}

// AddAdmin assigns the admin role to a user for the team
func (w *teamWrapper) AddAdmin(user *userWrapper) *teamWrapper {
	return w.addUserRole(user, authorization.AdminRole)
}
