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

func newResourceWrapper(g *TestGraph, params []interface{}) resourceWrapper {
	w := resourceWrapper{baseWrapper: baseWrapper{g}}

	var resourceName *string
	var resourceType *resourcetype.ResourceType
	var parentResource *resource.Resource

	for i := range params {
		switch t := params[i].(type) {
		case string:
			resourceName = &t
		case *string:
			resourceName = t
		case resourceTypeWrapper:
			resourceType = t.resourceType
		case *resourceTypeWrapper:
			resourceType = t.resourceType
		case resourceWrapper:
			parentResource = t.Resource()
		case *resourceWrapper:
			parentResource = t.Resource()
		case spaceWrapper:
			parentResource = t.Resource()
		case *spaceWrapper:
			parentResource = t.Resource()
		case organizationWrapper:
			parentResource = t.Resource()
		case *organizationWrapper:
			parentResource = t.Resource()
		case resource.Resource:
			parentResource = &t
		case *resource.Resource:
			parentResource = t
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
		ParentResource: parentResource,
	}

	if parentResource != nil {
		w.resource.ParentResourceID = &parentResource.ResourceID
	}

	err := g.app.ResourceRepository().Create(g.ctx, w.resource)
	require.NoError(g.t, err)

	return w
}

func loadResourceWrapper(g *TestGraph, resourceID string) resourceWrapper {
	w := resourceWrapper{baseWrapper: baseWrapper{g}}

	var native resource.Resource
	err := w.graph.db.Table("resource").Where("resource_id = ?", resourceID).Find(&native).Error
	require.NoError(w.graph.t, err)

	w.resource = &native

	return w
}

func (w *resourceWrapper) Resource() *resource.Resource {
	return w.resource
}

func (w *resourceWrapper) ResourceID() string {
	return w.resource.ResourceID
}
