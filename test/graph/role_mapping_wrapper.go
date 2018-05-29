package graph

import (
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

	var resource *resourceWrapper
	var fromRole *role.Role
	var toRole *role.Role

	for i := range params {
		switch t := params[i].(type) {
		case resourceWrapper:
			resource = &t
		case *resourceWrapper:
			resource = t
		case roleWrapper:
			if fromRole == nil {
				fromRole = t.role
			} else if toRole == nil {
				toRole = t.role
			}
		}
	}

	if resource == nil {
		resource = w.graph.CreateResource()
	}

	if fromRole == nil {
		resourceType := w.graph.LoadResourceType(resource.Resource().ResourceTypeID)
		fromRole = w.graph.CreateRole(resourceType).Role()
	}

	if toRole == nil {
		toRole = w.graph.CreateRole().Role()
	}

	w.mapping = &role.RoleMapping{
		ResourceID: resource.Resource().ResourceID,
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
