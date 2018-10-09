package graph

import (
	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	res "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	rolePkg "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/stretchr/testify/require"
)

// identityRoleWrapper represents a user domain object
type identityRoleWrapper struct {
	baseWrapper
	identityRole *rolePkg.IdentityRole
}

func newIdentityRoleWrapper(g *TestGraph, params []interface{}) interface{} {
	w := identityRoleWrapper{baseWrapper: baseWrapper{g}}

	var identity *account.Identity
	var resource *res.Resource
	var role *rolePkg.Role

	for i := range params {
		switch t := params[i].(type) {
		case organizationWrapper:
			identity = t.Identity()
		case *organizationWrapper:
			identity = t.Identity()
		case teamWrapper:
			identity = t.Identity()
		case *teamWrapper:
			identity = t.Identity()
		case userWrapper:
			identity = t.Identity()
		case *userWrapper:
			identity = t.Identity()
		case identityWrapper:
			identity = t.Identity()
		case *identityWrapper:
			identity = t.Identity()
		case resourceWrapper:
			resource = t.Resource()
		case *resourceWrapper:
			resource = t.Resource()
		case roleWrapper:
			role = t.Role()
		case *roleWrapper:
			role = t.Role()
		}
	}

	if identity == nil {
		identity = w.graph.CreateUser().Identity()
	}

	if resource == nil {
		if role != nil {
			resource = w.graph.CreateResource(w.graph.LoadResourceType(role.ResourceTypeID)).Resource()
		} else {
			resource = w.graph.CreateResource().Resource()
		}
	}

	if role == nil {
		role = w.graph.CreateRole(w.graph.LoadResourceType(resource.ResourceTypeID)).Role()
	}

	w.identityRole = &rolePkg.IdentityRole{
		IdentityID: identity.ID,
		ResourceID: resource.ResourceID,
		RoleID:     role.RoleID,
	}

	err := g.app.IdentityRoleRepository().Create(g.ctx, w.identityRole)
	require.NoError(g.t, err)

	return &w
}

func (w *identityRoleWrapper) IdentityRole() *rolePkg.IdentityRole {
	return w.identityRole
}

func (w *identityRoleWrapper) Delete() {
	w.graph.app.IdentityRoleRepository().Delete(w.graph.ctx, w.identityRole.IdentityRoleID)
}
