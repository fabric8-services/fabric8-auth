package service

import (
	"context"
	"fmt"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	"github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"

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
// IMPORTANT: This is a transactional method, which manages its own transaction/s internally
func (s *resourceServiceImpl) Delete(ctx context.Context, resourceID string) error {

	err := s.ExecuteInTransaction(func() error {
		return s.delete(ctx, resourceID, make(map[string]bool))
	})

	return err
}

func (s *resourceServiceImpl) delete(ctx context.Context, resourceID string, visitedChildren map[string]bool) error {
	// TODO delete associated identities where identities.identity_resource_id = resource.resource_id

	// Delete children

	// visitedChildren is used to make sure we don't have cycle resource references
	visitedChildren[resourceID] = true
	children, err := s.Repositories().ResourceRepository().LoadChildren(ctx, resourceID)
	if err != nil {
		return err
	}
	for _, child := range children {
		_, alreadyVisited := visitedChildren[child.ResourceID]
		if alreadyVisited {
			return errors.NewInternalErrorFromString(ctx, fmt.Sprintf("cycle resource references detected for resource %s with parent %s", child.ResourceID, resourceID))
		}
		err := s.delete(ctx, child.ResourceID, visitedChildren)
		if err != nil {
			return err
		}
	}

	// Delete role mapping
	err = s.Repositories().RoleMappingRepository().DeleteForResource(ctx, resourceID)
	if err != nil {
		return err
	}

	// Delete identity roles
	err = s.Repositories().IdentityRoleRepository().DeleteForResource(ctx, resourceID)
	if err != nil {
		return err
	}

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

		// Create a new resource instance
		res = &resource.Resource{
			ResourceID:       rID,
			ParentResourceID: parentResourceID,
			ResourceType:     *resourceType,
			ResourceTypeID:   resourceType.ResourceTypeID,
			ParentResource:   parentResource,
		}

		// Persist the resource
		err = s.Repositories().ResourceRepository().Create(ctx, res)
		if err != nil {
			return err
		}

		// Search for any default role mappings for the resource type
		defaultRoleMappings, err := s.Repositories().DefaultRoleMappingRepository().FindForResourceType(ctx, resourceType.ResourceTypeID)
		if err != nil {
			return err
		}

		// For each default role mapping for the same resource type, create a role mapping for the resource
		for _, m := range defaultRoleMappings {
			roleMapping := &repository.RoleMapping{
				ResourceID: rID,
				FromRoleID: m.FromRoleID,
				ToRoleID:   m.ToRoleID,
			}

			err = s.Repositories().RoleMappingRepository().Create(ctx, roleMapping)
			if err != nil {
				return err
			}
		}

		return nil
	})

	return res, err
}
