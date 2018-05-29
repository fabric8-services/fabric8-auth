package service

import (
	"context"

	"github.com/fabric8-services/fabric8-auth/app"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	"github.com/fabric8-services/fabric8-auth/errors"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/satori/go.uuid"
)

// resourceServiceImpl is the implementation of the interface for
// ResourceService.
type resourceServiceImpl struct {
	base.BaseService
}

// NewResourceService creates a new service.
func NewResourceService(context *servicecontext.ServiceContext) service.ResourceService {
	return &resourceServiceImpl{base.NewBaseService(context)}
}

// Delete deletes the resource with resourceID
func (s *resourceServiceImpl) Delete(ctx context.Context, resourceID string) error {

	return s.Repositories().ResourceRepository().Delete(ctx, resourceID)
}

// Read reads resource
func (s *resourceServiceImpl) Read(ctx context.Context, resourceID string) (*app.Resource, error) {

	res, err := s.Repositories().ResourceRepository().Load(ctx, resourceID)
	if err != nil {
		return nil, err
	}

	// Load the resource type scopes
	scopes, err := s.Repositories().ResourceTypeScopeRepository().LookupForType(ctx, res.ResourceTypeID)
	if err != nil {
		return nil, errors.NewInternalError(ctx, err)
	}

	var scopeValues []string

	for index := range scopes {
		scopeValues = append(scopeValues, scopes[index].Name)
	}

	return &app.Resource{
		ResourceID:       &res.ResourceID,
		Type:             &res.ResourceType.Name,
		ParentResourceID: res.ParentResourceID,
		ResourceScopes:   scopeValues,
	}, nil
}

// Register registers/creates a new resource
// IMPORTANT: This is a transactional method, which manages its own transaction/s internally
func (s *resourceServiceImpl) Register(ctx context.Context, resourceTypeName string, resourceID, parentResourceID *string) (*resource.Resource, error) {

	var res *resource.Resource

	err := s.ExecuteInTransaction(func() error {

		// Lookup the resource type
		resourceType, err := s.Repositories().ResourceTypeRepository().Lookup(ctx, resourceTypeName)
		if err != nil {
			return errors.NewBadParameterErrorFromString("type", resourceTypeName, err.Error())
		}

		// Lookup the parent resource if it's specified
		var parentResource *resource.Resource

		if parentResourceID != nil {
			parentResource, err = s.Repositories().ResourceRepository().Load(ctx, *parentResourceID)
			if err != nil {
				return errors.NewBadParameterErrorFromString("parent resource ID", *parentResourceID, err.Error())
			}
		}

		var rID string
		if resourceID != nil {
			rID = *resourceID
		} else {
			rID = uuid.NewV4().String()
		}

		var parentResourceID *string

		if parentResource != nil {
			parentResourceID = &parentResource.ResourceID
		}

		// Create a new resource instance
		res = &resource.Resource{
			ResourceID:       rID,
			ParentResourceID: parentResourceID,
			ResourceType:     *resourceType,
			ResourceTypeID:   resourceType.ResourceTypeID,
			ParentResource:   parentResource,
		}

		// Persist the resource
		return s.Repositories().ResourceRepository().Create(ctx, res)
	})

	return res, err
}
