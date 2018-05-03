package graph

import (
	"database/sql"
	account "github.com/fabric8-services/fabric8-auth/account/repository"
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

func newTeamWrapper(g *TestGraph, params []interface{}) teamWrapper {
	w := teamWrapper{baseWrapper: baseWrapper{g}}

	var teamName *string
	var space *resource.Resource

	for i := range params {
		switch t := params[i].(type) {
		case string:
			teamName = &t
		case *spaceWrapper:
			space = t.Resource()
		case spaceWrapper:
			space = t.Resource()
		}
	}

	if space == nil {
		space = w.graph.CreateSpace().Resource()
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

	err = g.app.Identities().Create(g.ctx, w.identity)
	require.NoError(g.t, err)

	return w
}

func (w *teamWrapper) TeamID() uuid.UUID {
	return w.identity.ID
}

func (w *teamWrapper) TeamName() string {
	return w.identity.IdentityResource.Name
}

func (w *teamWrapper) Identity() *account.Identity {
	return w.identity
}

func (w *teamWrapper) AddMember(wrapper interface{}) *teamWrapper {
	identityID := w.identityIDFromWrapper(wrapper)

	err := w.graph.db.Exec("INSERT INTO membership (member_id, member_of) VALUES (?, ?)", identityID, w.identity.ID).Error
	require.NoError(w.graph.t, err)
	return w
}

func (w *teamWrapper) addUserRole(identityID uuid.UUID, roleName string) *teamWrapper {
	r, err := w.graph.app.RoleRepository().Lookup(w.graph.ctx, roleName, authorization.IdentityResourceTypeTeam)
	require.NoError(w.graph.t, err)

	identityRole := &role.IdentityRole{
		ResourceID: w.identity.IdentityResourceID.String,
		IdentityID: identityID,
		RoleID:     r.RoleID,
	}

	err = w.graph.app.IdentityRoleRepository().Create(w.graph.ctx, identityRole)
	require.NoError(w.graph.t, err)
	return w
}

// AddAdmin assigns the admin role to a user for the team
func (w *teamWrapper) AddAdmin(wrapper interface{}) *teamWrapper {
	return w.addUserRole(w.identityIDFromWrapper(wrapper), authorization.AdminRole)
}
