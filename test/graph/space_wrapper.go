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
	resource       *resource.Resource
	parentResource *resource.Resource
}

func newSpaceWrapper(g *TestGraph, params []interface{}) spaceWrapper {
	w := spaceWrapper{baseWrapper: baseWrapper{g}}

	resourceType, err := g.app.ResourceTypeRepository().Lookup(g.ctx, authorization.ResourceTypeSpace)
	require.NoError(g.t, err)

	var resourceID *string
	for i := range params {
		switch t := params[i].(type) {
		case *organizationWrapper:
			w.parentResource = t.Resource()
		case organizationWrapper:
			w.parentResource = t.Resource()
		case *resourceWrapper:
			w.parentResource = t.Resource()
		case resourceWrapper:
			w.parentResource = t.Resource()
		case *string:
			resourceID = t
		case string:
			resourceID = &t
		}
	}

	var parentResourceID *string
	if w.parentResource != nil {
		parentResourceID = &w.parentResource.ResourceID
	}
	w.resource, err = g.app.ResourceService().Register(g.ctx, resourceType.Name, resourceID, parentResourceID)
	require.NoError(g.t, err)

	return w
}

func (w *spaceWrapper) addUserRole(identityID uuid.UUID, roleName string) *spaceWrapper {
	r, err := w.graph.app.RoleRepository().Lookup(w.graph.ctx, roleName, authorization.ResourceTypeSpace)
	require.NoError(w.graph.t, err)

	identityRole := &role.IdentityRole{
		ResourceID: w.resource.ResourceID,
		IdentityID: identityID,
		RoleID:     r.RoleID,
	}

	err = w.graph.app.IdentityRoleRepository().Create(w.graph.ctx, identityRole)
	require.NoError(w.graph.t, err)
	return w
}

// AddAdmin assigns the admin role to a user for the space
func (w *spaceWrapper) AddAdmin(wrapper interface{}) *spaceWrapper {
	return w.addUserRole(w.identityIDFromWrapper(wrapper), authorization.SpaceAdminRole)
}

// AddContributor assigns the admin role to a user for the space
func (w *spaceWrapper) AddContributor(wrapper interface{}) *spaceWrapper {
	return w.addUserRole(w.identityIDFromWrapper(wrapper), authorization.SpaceContributorRole)
}

// AddViewer assigns the admin role to a user for the space
func (w *spaceWrapper) AddViewer(wrapper interface{}) *spaceWrapper {
	return w.addUserRole(w.identityIDFromWrapper(wrapper), authorization.SpaceViewerRole)
}

func (w *spaceWrapper) Resource() *resource.Resource {
	return w.resource
}

func (w *spaceWrapper) SpaceID() string {
	return w.resource.ResourceID
}
