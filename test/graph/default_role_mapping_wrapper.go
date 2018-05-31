package graph

import (
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/stretchr/testify/require"
)

// defaultRoleMappingWrapper represents a default role mapping domain object
type defaultRoleMappingWrapper struct {
	baseWrapper
	mapping *role.DefaultRoleMapping
}

func newDefaultRoleMappingWrapper(g *TestGraph, params []interface{}) defaultRoleMappingWrapper {
	w := defaultRoleMappingWrapper{baseWrapper: baseWrapper{g}}

	var resourceType *resourceTypeWrapper
	var fromRole *role.Role
	var toRole *role.Role

	for i := range params {
		switch t := params[i].(type) {
		case resourceTypeWrapper:
			resourceType = &t
		case *resourceTypeWrapper:
			resourceType = t
		case roleWrapper:
			if fromRole == nil {
				fromRole = t.role
			} else if toRole == nil {
				toRole = t.role
			}
		}
	}

	if resourceType == nil {
		resourceType = w.graph.CreateResourceType()
	}

	if fromRole == nil {
		fromRole = w.graph.CreateRole(resourceType).Role()
	}

	if toRole == nil {
		toRole = w.graph.CreateRole().Role()
	}

	w.mapping = &role.DefaultRoleMapping{
		ResourceTypeID: resourceType.ResourceType().ResourceTypeID,
		FromRoleID:     fromRole.RoleID,
		ToRoleID:       toRole.RoleID,
	}

	err := g.app.DefaultRoleMappingRepository().Create(g.ctx, w.mapping)
	require.NoError(g.t, err)

	return w
}

func (g *defaultRoleMappingWrapper) DefaultRoleMapping() *role.DefaultRoleMapping {
	return g.mapping
}
