package service

import (
	"context"
	"fmt"
	"github.com/fabric8-services/fabric8-auth/application/repository"
	"github.com/fabric8-services/fabric8-auth/application/transaction"
	"github.com/fabric8-services/fabric8-auth/authorization"
	permservice "github.com/fabric8-services/fabric8-auth/authorization/permission/service"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
	rolerepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/satori/go.uuid"
)

// RoleManagementService defines the service contract for managing role assignments
type RoleManagementService interface {
	ListByResource(ctx context.Context, resourceID string) ([]rolerepo.IdentityRole, error)
	ListAvailableRolesByResourceType(ctx context.Context, resourceType string) ([]role.RoleDescriptor, error)
	ListByResourceAndRoleName(ctx context.Context, resourceID string, roleName string) ([]rolerepo.IdentityRole, error)
	Assign(ctx context.Context, assignedBy uuid.UUID, identitiesToBeAssigned []uuid.UUID, resourceID string, roleName string) error
}

// NewRoleManagementService creates a new service to manage role assignments
func NewRoleManagementService(repo repository.Repositories, tm transaction.TransactionManager) *RoleManagementServiceImpl {
	return &RoleManagementServiceImpl{repo: repo, tm: tm}
}

// RoleManagementServiceImpl implements the RoleManagementService to manage role assignments
type RoleManagementServiceImpl struct {
	repo repository.Repositories
	tm   transaction.TransactionManager
}

// ListByResourceAndRoleName lists role assignments of a specific resource.
func (r *RoleManagementServiceImpl) ListByResourceAndRoleName(ctx context.Context, resourceID string, roleName string) ([]rolerepo.IdentityRole, error) {
	return r.repo.IdentityRoleRepository().FindIdentityRolesByResourceAndRoleName(ctx, resourceID, roleName)
}

// ListByResource lists role assignments of a specific resource.
func (r *RoleManagementServiceImpl) ListByResource(ctx context.Context, resourceID string) ([]rolerepo.IdentityRole, error) {
	return r.repo.IdentityRoleRepository().FindIdentityRolesByResource(ctx, resourceID)
}

// ListAvailableRolesByResourceType lists role assignments of a specific resource.
func (r *RoleManagementServiceImpl) ListAvailableRolesByResourceType(ctx context.Context, resourceType string) ([]role.RoleDescriptor, error) {
	return r.repo.RoleRepository().FindRolesByResourceType(ctx, resourceType)
}

// assign assigns an identity ( users or organizations or teams or groups ) with a role, for a specific resource
// IMPORTANT: This is a transactional method, which manages its own transaction/s internally
func (r *RoleManagementServiceImpl) assign(ctx context.Context, identityID uuid.UUID, resourceID string, roleName string) error {

	err := transaction.Transactional(r.tm, func(tr transaction.TransactionalResources) error {

		rt, err := r.repo.ResourceRepository().Load(ctx, resourceID)

		if err != nil {
			return err
		}

		roleRef, err := r.repo.RoleRepository().Lookup(ctx, roleName, rt.ResourceType.Name)
		if err != nil {
			return err
		}

		ir := rolerepo.IdentityRole{
			ResourceID: resourceID,
			IdentityID: identityID,
			RoleID:     roleRef.RoleID,
		}

		return r.repo.IdentityRoleRepository().Create(ctx, &ir)
	})

	return err
}

// Assign assigns an identity ( users or organizations or teams or groups ) with a role, for a specific resource
// IMPORTANT: This is a transactional method, which manages its own transaction/s internally
func (r *RoleManagementServiceImpl) Assign(ctx context.Context, assignedBy uuid.UUID, identitiesToBeAssigned []uuid.UUID, resourceID string, roleName string) error {
	// check if the current user token belongs to a user who has the necessary privileges
	// for assigning roles to other users.

	permissionService := permservice.NewPermissionService(r.repo)
	hasScope, err := permissionService.HasScope(ctx, assignedBy, resourceID, authorization.ManageTeamsInSpaceScope)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": resourceID,
			"identity_id": assignedBy,
			"role":        roleName,
		}, "error determining if user has manage scope")
		return err
	}
	if !hasScope {
		log.Error(ctx, map[string]interface{}{
			"resource_id": resourceID,
			"identity_id": assignedBy,
			"role":        roleName,
		}, "user not authorizied to assign roles")
		return errors.NewForbiddenError("user is not authorized to assign roles")
	}

	// In batch assignment of roles all selected users must have previously been assigned
	// privileges for the resource, otherwise the invitation workflow should be used instead
	for _, identityIDAsUUID := range identitiesToBeAssigned {
		assignedRoles, err := r.repo.IdentityRoleRepository().FindIdentityRolesByIdentityAndResource(ctx, resourceID, identityIDAsUUID)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"resource_id": resourceID,
				"identity_id": assignedBy,
				"role":        roleName,
			}, "error looking up existing assignments")
			return err
		}
		if len(assignedRoles) == 0 {
			log.Error(ctx, map[string]interface{}{
				"resource_id": resourceID,
				"identity_id": identityIDAsUUID,
				"role":        roleName,
			}, "identity not part of a resource cannot be assigned a role")
			return errors.NewBadParameterErrorFromString("identityID", identityIDAsUUID, fmt.Sprintf("cannot update roles for an identity %s without an existing role", identityIDAsUUID))
		}
	}

	// Now that we have confirmed that all users have pre-existing role assignments
	// we can proceed with the assignment of roles.
	for _, identityIDAsUUID := range identitiesToBeAssigned {
		err = r.assign(ctx, identityIDAsUUID, resourceID, roleName)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"resource_id": resourceID,
				"identity_id": identityIDAsUUID,
				"role":        roleName,
			}, "assignment failed")
			return err
		}
	}

	return nil
}
