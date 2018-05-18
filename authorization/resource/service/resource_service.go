package service

import (
	"context"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application/repository"
	"github.com/fabric8-services/fabric8-auth/application/transaction"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	"github.com/fabric8-services/fabric8-auth/errors"

	"github.com/satori/go.uuid"
)

type ResourceService interface {
	Delete(ctx context.Context, resourceID string) error
	Read(ctx context.Context, resourceID string) (*app.Resource, error)
	Register(ctx context.Context, resourceTypeName string, resourceID, parentResourceID *string) (*resource.Resource, error)
}

// resourceServiceImpl is the implementation of the interface for
// ResourceService.
type resourceServiceImpl struct {
	repo repository.Repositories
	tm   transaction.TransactionManager
}

// NewResourceService creates a new service.
func NewResourceService(repo repository.Repositories, tm transaction.TransactionManager) ResourceService {
	return &resourceServiceImpl{repo: repo, tm: tm}
}

// Delete deletes the resource with resourceID
func (s *resourceServiceImpl) Delete(ctx context.Context, resourceID string) error {

	return s.repo.ResourceRepository().Delete(ctx, resourceID)
}

// Read reads resource
func (s *resourceServiceImpl) Read(ctx context.Context, resourceID string) (*app.Resource, error) {

	res, err := s.repo.ResourceRepository().Load(ctx, resourceID)
	if err != nil {
		return nil, err
	}

	// Load the resource type scopes
	scopes, err := s.repo.ResourceTypeScopeRepository().LookupForType(ctx, res.ResourceTypeID)
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

	err := transaction.Transactional(s.tm, func(tr transaction.TransactionalResources) error {

		// Lookup the resource type
		resourceType, err := tr.ResourceTypeRepository().Lookup(ctx, resourceTypeName)
		if err != nil {
			return errors.NewBadParameterErrorFromString("type", resourceTypeName, err.Error())
		}

		// Lookup the parent resource if it's specified
		var parentResource *resource.Resource

		if parentResourceID != nil {
			parentResource, err = tr.ResourceRepository().Load(ctx, *parentResourceID)
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
		return tr.ResourceRepository().Create(ctx, res)
	})

	return res, err
}
