package graph

import (
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"

	"github.com/stretchr/testify/require"
)

// roleMappingWrapper represents a default role mapping domain object
type roleMappingWrapper struct {
	baseWrapper
	mapping *role.RoleMapping
}

func newRoleMappingWrapper(g *TestGraph, params []interface{}) roleMappingWrapper {
	w := roleMappingWrapper{baseWrapper: baseWrapper{g}}

	var resource *resource.Resource
	var fromRole *role.Role
	var toRole *role.Role

	for i := range params {
		switch t := params[i].(type) {
		case resourceWrapper:
			resource = t.Resource()
		case *resourceWrapper:
			resource = t.Resource()
		case spaceWrapper:
			resource = t.Resource()
		case *spaceWrapper:
			resource = t.Resource()
		case roleWrapper:
			if fromRole == nil {
				fromRole = t.role
			} else if toRole == nil {
				toRole = t.role
			}
		}
	}

	if resource == nil {
		resource = w.graph.CreateResource().Resource()
	}

	if fromRole == nil {
		resourceType := w.graph.LoadResourceType(resource.ResourceTypeID)
		fromRole = w.graph.CreateRole(resourceType).Role()
	}

	if toRole == nil {
		toRole = w.graph.CreateRole().Role()
	}

	w.mapping = &role.RoleMapping{
		ResourceID: resource.ResourceID,
		FromRoleID: fromRole.RoleID,
		ToRoleID:   toRole.RoleID,
	}

	err := g.app.RoleMappingRepository().Create(g.ctx, w.mapping)
	require.NoError(g.t, err)

	return w
}

func (g *roleMappingWrapper) RoleMapping() *role.RoleMapping {
	return g.mapping
}
