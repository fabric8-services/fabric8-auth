package graph

import (
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/stretchr/testify/require"
)

// defaultRoleMappingWrapper represents a default role mapping domain object
type defaultRoleMappingWrapper struct {
	baseWrapper
	mapping *role.DefaultRoleMapping
}

func newDefaultRoleMappingWrapper(g *TestGraph, params []interface{}) interface{} {
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
		case *roleWrapper:
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
	// check if the same default role mapping already exists to avoid duplicate entries (forbidden by unique constraint in the db)
	existingDRM, err := g.app.DefaultRoleMappingRepository().FindForResourceTypeAndRoles(g.ctx, w.mapping.ResourceTypeID, w.mapping.FromRoleID, w.mapping.ToRoleID)
	if ok, _ := errors.IsNotFoundError(err); ok {
		err := g.app.DefaultRoleMappingRepository().Create(g.ctx, w.mapping)
		require.NoError(g.t, err)
	} else {
		require.NoError(g.t, err)
		w.mapping = existingDRM
	}
	return &w
}

func (g *defaultRoleMappingWrapper) DefaultRoleMapping() *role.DefaultRoleMapping {
	return g.mapping
}
