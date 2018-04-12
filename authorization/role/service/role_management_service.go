package service

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application"
	role "github.com/fabric8-services/fabric8-auth/authorization/role"
	roleModel "github.com/fabric8-services/fabric8-auth/authorization/role/model"
	rolerepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"

	"github.com/fabric8-services/fabric8-auth/log"
	uuid "github.com/satori/go.uuid"
)

// RoleManagementService defines the contract for managing roles assigments to a resource
type RoleManagementService interface {
	ListAssignmentsByIdentityAndResource(ctx context.Context, resourceID string, identity uuid.UUID) ([]rolerepo.IdentityRole, error)
	Assign(ctx context.Context, identityID []uuid.UUID, resourceID string, roleName string) error
	ListByResource(ctx context.Context, resourceID string) ([]rolerepo.IdentityRole, error)
	ListByResourceAndRoleName(ctx context.Context, resourceID string, roleName string) ([]rolerepo.IdentityRole, error)
	ListAvailableRolesByResourceType(ctx context.Context, resourceType string) ([]role.RoleScope, error)
}

// RoleManagementServiceImpl implements the RoleManagementService for managing role assignments.
type RoleManagementServiceImpl struct {
	modelService roleModel.RoleManagementModelService
	db           application.DB
}

// NewRoleManagementService creates a reference to new RoleManagementService implementation
func NewRoleManagementService(modelService roleModel.RoleManagementModelService, db application.DB) *RoleManagementServiceImpl {
	return &RoleManagementServiceImpl{modelService: modelService, db: db}
}

// ListByResource lists assignments made for a specific resource
func (r *RoleManagementServiceImpl) ListByResource(ctx context.Context, resourceID string) ([]rolerepo.IdentityRole, error) {

	var roles []rolerepo.IdentityRole
	var err error
	err = application.Transactional(r.db, func(appl application.Application) error {
		err = appl.ResourceRepository().CheckExists(ctx, resourceID)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"resource_id": resourceID,
				"err":         err,
			}, "does not exist")
			return errors.NewNotFoundError("resource_id", resourceID)
		}

		roles, err = r.modelService.ListByResource(ctx, resourceID)
		return err
	})

	return roles, err
}

// ListAssignmentsByIdentityAndResource lists all the roles that have been assigned to a specific user/identity for a specific resource
func (r *RoleManagementServiceImpl) ListAssignmentsByIdentityAndResource(ctx context.Context, resourceID string, identityID uuid.UUID) ([]rolerepo.IdentityRole, error) {
	var roles []rolerepo.IdentityRole
	var err error
	err = application.Transactional(r.db, func(appl application.Application) error {
		roles, err = r.modelService.ListAssignmentsByIdentityAndResource(ctx, resourceID, identityID)
		return err
	})
	return roles, err
}

// ListAvailableRolesByResourceType lists assignments made for a specific resource type
func (r *RoleManagementServiceImpl) ListAvailableRolesByResourceType(ctx context.Context, resourceType string) ([]role.RoleScope, error) {

	var roleScopes []role.RoleScope
	var err error
	err = application.Transactional(r.db, func(appl application.Application) error {
		_, err = appl.ResourceTypeRepository().Lookup(ctx, resourceType)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"resource_type": resourceType,
				"err":           err,
			}, "error getting toles for the resource type")
			// if not found, then NotFoundError would be returned,
			// hence returning the error as is.
			return err
		}

		roleScopes, err = r.modelService.ListAvailableRolesByResourceType(ctx, resourceType)
		return err
	})
	return roleScopes, err
}

// ListByResourceAndRoleName lists assignments made for a specific resource
func (r *RoleManagementServiceImpl) ListByResourceAndRoleName(ctx context.Context, resourceID string, roleName string) ([]rolerepo.IdentityRole, error) {

	var roles []rolerepo.IdentityRole
	var err error
	err = application.Transactional(r.db, func(appl application.Application) error {
		err = appl.ResourceRepository().CheckExists(ctx, resourceID)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"resource_id": resourceID,
				"err":         err,
			}, "does not exist")
			return errors.NewNotFoundError("resource_id", resourceID)
		}

		roles, err = r.modelService.ListByResourceAndRoleName(ctx, resourceID, roleName)
		return err
	})

	return roles, err
}

// Assign assigns a user/identity to role, for a specific resource
func (r *RoleManagementServiceImpl) Assign(ctx context.Context, identityIDs []uuid.UUID, resourceID string, roleName string) error {

	// TODO: Check if the user is authorized to assign roles to other users.
	var err error
	return application.Transactional(r.db, func(appl application.Application) error {
		err = appl.ResourceRepository().CheckExists(ctx, resourceID)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"resource_id": resourceID,
				"err":         err,
			}, "does not exist")
			return errors.NewNotFoundError("resource_id", resourceID)
		}

		for _, identityID := range identityIDs {
			err = r.modelService.Assign(ctx, identityID, resourceID, roleName)
			if err != nil {
				// if any one fails, we return err - that should trigger a transaction rollback
				return errors.NewInternalError(ctx, err)
			}
		}
		return err
	})
}
