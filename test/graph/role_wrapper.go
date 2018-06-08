package graph

import (
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
)

// roleWrapper represents a resource domain object
type roleWrapper struct {
	baseWrapper
	role *role.Role
}

func newRoleWrapper(g *TestGraph, params []interface{}) interface{} {
	w := roleWrapper{baseWrapper: baseWrapper{g}}

	var roleName *string
	var resourceType *resourcetype.ResourceType

	for i := range params {
		switch t := params[i].(type) {
		case string:
			roleName = &t
		case resourceTypeWrapper:
			resourceType = t.resourceType
		case *resourceTypeWrapper:
			resourceType = t.resourceType
		case resourcetype.ResourceType:
			resourceType = &t
		case *resourcetype.ResourceType:
			resourceType = t
		}
	}

	if resourceType == nil {
		resourceType = w.graph.CreateResourceType().ResourceType()
	}

	if roleName == nil {
		nm := "Role-" + uuid.NewV4().String()
		roleName = &nm
	}

	w.role = &role.Role{
		Name:           *roleName,
		ResourceTypeID: resourceType.ResourceTypeID,
	}

	err := g.app.RoleRepository().Create(g.ctx, w.role)
	require.NoError(g.t, err)

	return &w
}

func (g *roleWrapper) Role() *role.Role {
	return g.role
}
