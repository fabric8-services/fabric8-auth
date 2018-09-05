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

func loadResourceTypeWrapper(g *TestGraph, resourceTypeID *uuid.UUID, resourceTypeName *string) resourceTypeWrapper {
	w := resourceTypeWrapper{baseWrapper: baseWrapper{g}}

	var native resourcetype.ResourceType
	q := w.graph.db.Table("resource_type")
	if resourceTypeID != nil {
		q = q.Where("resource_type_id = ?", *resourceTypeID)
	} else if resourceTypeName != nil {
		q = q.Where("name = ?", *resourceTypeName)
	}

	err := q.Find(&native).Error
	require.NoError(w.graph.t, err)

	w.resourceType = &native
	return w
}

func newResourceTypeWrapper(g *TestGraph, params []interface{}) interface{} {
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

	return &w
}

func (w *resourceTypeWrapper) ResourceType() *resourcetype.ResourceType {
	return w.resourceType
}

func (w *resourceTypeWrapper) Name() string {
	return w.resourceType.Name
}

func (w *resourceTypeWrapper) AddScope(scope string) {
	rts := &resourcetype.ResourceTypeScope{
		ResourceTypeID: w.resourceType.ResourceTypeID,
		Name:           scope,
	}
	err := w.graph.app.ResourceTypeScopeRepository().Create(w.graph.ctx, rts)
	require.NoError(w.graph.t, err)
}
