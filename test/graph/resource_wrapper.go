package graph

import (
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
)

// resourceWrapper represents a resource domain object
type resourceWrapper struct {
	baseWrapper
	resource *resource.Resource
}

func newResourceWrapper(g *TestGraph, params ...interface{}) resourceWrapper {
	w := resourceWrapper{baseWrapper: baseWrapper{g}}

	var resourceName *string
	var resourceType *resourcetype.ResourceType

	for i := range params {
		switch t := params[i].(type) {
		case string:
			resourceName = &t
		case resourceTypeWrapper:
			resourceType = t.resourceType
		}
	}

	if resourceType == nil {
		resourceType = w.graph.CreateResourceType().ResourceType()
	}

	if resourceName == nil {
		nm := "Resource-" + uuid.NewV4().String()
		resourceName = &nm
	}

	w.resource = &resource.Resource{
		Name:           *resourceName,
		ResourceTypeID: resourceType.ResourceTypeID,
	}

	err := g.app.ResourceRepository().Create(g.ctx, w.resource)
	require.NoError(g.t, err)

	return w
}

func (g *resourceWrapper) Resource() *resource.Resource {
	return g.resource
}
