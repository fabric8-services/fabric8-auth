package graph

import (
	"database/sql"

	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/authorization"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	rolerepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
)

// teamWrapper represents a team resource domain object
type teamWrapper struct {
	baseWrapper
	identity *account.Identity
	resource *resource.Resource
}

func loadTeamWrapper(g *TestGraph, teamID uuid.UUID) teamWrapper {
	w := teamWrapper{baseWrapper: baseWrapper{g}}

	var native account.Identity
	err := w.graph.db.Table("identities").Preload("IdentityResource").Where("ID = ?", teamID).Find(&native).Error
	require.NoError(w.graph.t, err)

	w.identity = &native
	w.resource = &native.IdentityResource

	return w
}

func newTeamWrapper(g *TestGraph, params []interface{}) interface{} {
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

	w.resource = &resource.Resource{
		Name:             *teamName,
		ResourceType:     *resourceType,
		ResourceTypeID:   resourceType.ResourceTypeID,
		ParentResourceID: &space.ResourceID,
	}

	err = g.app.ResourceRepository().Create(g.ctx, w.resource)
	require.NoError(g.t, err)
	w.resource.ParentResource = space

	w.identity = &account.Identity{
		ProviderType:       account.DefaultIDP,
		IdentityResourceID: sql.NullString{String: w.resource.ResourceID, Valid: true},
		IdentityResource:   *w.resource,
	}

	err = g.app.Identities().Create(g.ctx, w.identity)
	require.NoError(g.t, err)

	return &w
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

func (w *teamWrapper) Resource() *resource.Resource {
	return w.resource
}

func (w *teamWrapper) ResourceID() string {
	return w.resource.ResourceID
}

func (w *teamWrapper) AddMember(wrapper interface{}) *teamWrapper {
	identityID := identityIDFromWrapper(w.graph.t, wrapper)

	err := w.graph.app.Identities().AddMember(w.graph.ctx, w.identity.ID, identityID)
	require.NoError(w.graph.t, err)
	return w
}

func (w *teamWrapper) RemoveMember(wrapper interface{}) *teamWrapper {
	identityID := identityIDFromWrapper(w.graph.t, wrapper)

	err := w.graph.app.Identities().RemoveMember(w.graph.ctx, w.identity.ID, identityID)
	require.NoError(w.graph.t, err)
	return w
}

func (w *teamWrapper) AssignRole(identity *account.Identity, role *rolerepo.Role) {
	ir := &rolerepo.IdentityRole{
		IdentityID: identity.ID,
		ResourceID: w.resource.ResourceID,
		RoleID:     role.RoleID,
	}

	err := w.graph.app.IdentityRoleRepository().Create(w.graph.ctx, ir)
	require.NoError(w.graph.t, err)
}
