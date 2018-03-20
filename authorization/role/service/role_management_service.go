package service

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application"
	identityrole "github.com/fabric8-services/fabric8-auth/authorization/role/identityrole/repository"
	roleModel "github.com/fabric8-services/fabric8-auth/authorization/role/model"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
)

// RoleManagementService defines the contract for managing roles assigments to a resource
type RoleManagementService interface {
	ListByResource(ctx context.Context, resourceID string) ([]identityrole.IdentityRole, error)
	ListByResourceAndRoleName(ctx context.Context, resourceID string, roleName string) ([]identityrole.IdentityRole, error)
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
func (r *RoleManagementServiceImpl) ListByResource(ctx context.Context, resourceID string) ([]identityrole.IdentityRole, error) {

	var roles []identityrole.IdentityRole
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

// ListByResourceAndRoleName lists assignments made for a specific resource
func (r *RoleManagementServiceImpl) ListByResourceAndRoleName(ctx context.Context, resourceID string, roleName string) ([]identityrole.IdentityRole, error) {

	var roles []identityrole.IdentityRole
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
