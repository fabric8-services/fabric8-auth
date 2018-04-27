package graph

import (
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
)

// resourceTypeWrapper represents a resource type domain object
type resourceTypeWrapper struct {
	baseWrapper
	resourceType *resourcetype.ResourceType
}

func newResourceTypeWrapper(g *TestGraph, params []interface{}) resourceTypeWrapper {
	w := resourceTypeWrapper{baseWrapper: baseWrapper{g}}

	var resourceTypeName *string
	for i := range params {
		switch t := params[i].(type) {
		case string:
			resourceTypeName = &t
		}
	}

	if resourceTypeName == nil {
		nm := "ResourceType-" + uuid.NewV4().String()
		resourceTypeName = &nm
	}

	w.resourceType = &resourcetype.ResourceType{
		Name: *resourceTypeName,
	}

	err := g.app.ResourceTypeRepository().Create(g.ctx, w.resourceType)
	require.NoError(g.t, err)

	return w
}

func (w *resourceTypeWrapper) ResourceType() *resourcetype.ResourceType {
	return w.resourceType
}
