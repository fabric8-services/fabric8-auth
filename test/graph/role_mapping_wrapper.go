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

	var resrc *resource.Resource
	var fromRole *role.Role
	var toRole *role.Role

	for i := range params {
		switch t := params[i].(type) {
		case resourceWrapper:
			resrc = t.Resource()
		case *resourceWrapper:
			resrc = t.Resource()
		case spaceWrapper:
			resrc = t.Resource()
		case *spaceWrapper:
			resrc = t.Resource()
		case resource.Resource:
			resrc = &t
		case *resource.Resource:
			resrc = t
		case roleWrapper:
			if fromRole == nil {
				fromRole = t.role
			} else if toRole == nil {
				toRole = t.role
			}
		}
	}

	if resrc == nil {
		resrc = w.graph.CreateResource().Resource()
	}

	if fromRole == nil {
		resourceType := w.graph.LoadResourceType(resrc.ResourceTypeID)
		fromRole = w.graph.CreateRole(resourceType).Role()
	}

	if toRole == nil {
		toRole = w.graph.CreateRole().Role()
	}

	w.mapping = &role.RoleMapping{
		ResourceID: resrc.ResourceID,
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
