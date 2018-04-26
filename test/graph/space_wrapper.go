package graph

import (
	"github.com/fabric8-services/fabric8-auth/authorization"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
)

// spaceWrapper represents a space resource domain object
type spaceWrapper struct {
	baseWrapper
	resource *resource.Resource
}

func newSpaceWrapper(g *TestGraph, params ...interface{}) spaceWrapper {
	w := spaceWrapper{baseWrapper: baseWrapper{g}}

	resourceType, err := g.app.ResourceTypeRepository().Lookup(g.ctx, authorization.ResourceTypeSpace)
	require.NoError(g.t, err)

	w.resource = &resource.Resource{
		Name:           "Space-" + uuid.NewV4().String(),
		ResourceType:   *resourceType,
		ResourceTypeID: resourceType.ResourceTypeID,
	}

	err = g.app.ResourceRepository().Create(g.ctx, w.resource)
	require.NoError(g.t, err)

	return w
}

func (w *spaceWrapper) addUserRole(user *userWrapper, roleName string) *spaceWrapper {
	r, err := w.graph.app.RoleRepository().Lookup(w.graph.ctx, roleName, authorization.ResourceTypeSpace)
	require.NoError(w.graph.t, err)

	identityRole := &role.IdentityRole{
		ResourceID: w.resource.ResourceID,
		IdentityID: user.Identity().ID,
		RoleID:     r.RoleID,
	}

	err = w.graph.app.IdentityRoleRepository().Create(w.graph.ctx, identityRole)
	require.NoError(w.graph.t, err)
	return w
}

// AddAdmin assigns the admin role to a user for the space
func (w *spaceWrapper) AddAdmin(user *userWrapper) *spaceWrapper {
	return w.addUserRole(user, authorization.AdminRole)
}

// AddContributor assigns the admin role to a user for the space
func (w *spaceWrapper) AddContributor(user *userWrapper) *spaceWrapper {
	return w.addUserRole(user, authorization.SpaceContributorRole)
}

// AddViewer assigns the admin role to a user for the space
func (w *spaceWrapper) AddViewer(user *userWrapper) *spaceWrapper {
	return w.addUserRole(user, authorization.SpaceViewerRole)
}

func (w *spaceWrapper) Resource() *resource.Resource {
	return w.resource
}
