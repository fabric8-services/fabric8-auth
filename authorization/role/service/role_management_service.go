package service

import (
	"context"
	"fmt"

	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
	rolerepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/satori/go.uuid"
)

// NewRoleManagementService creates a new service to manage role assignments
func NewRoleManagementService(context *servicecontext.ServiceContext) *roleManagementServiceImpl {
	return &roleManagementServiceImpl{base.NewBaseService(context)}
}

// RoleManagementServiceImpl implements the RoleManagementService to manage role assignments
type roleManagementServiceImpl struct {
	base.BaseService
}

// ListByResourceAndRoleName lists role assignments of a specific resource.
func (r *roleManagementServiceImpl) ListByResourceAndRoleName(ctx context.Context, resourceID string, roleName string) ([]rolerepo.IdentityRole, error) {
	return r.Repositories().IdentityRoleRepository().FindIdentityRolesByResourceAndRoleName(ctx, resourceID, roleName)
}

// ListByResource lists role assignments of a specific resource.
func (r *roleManagementServiceImpl) ListByResource(ctx context.Context, resourceID string) ([]rolerepo.IdentityRole, error) {
	return r.Repositories().IdentityRoleRepository().FindIdentityRolesByResource(ctx, resourceID)
}

// ListAvailableRolesByResourceType lists role assignments of a specific resource.
func (r *roleManagementServiceImpl) ListAvailableRolesByResourceType(ctx context.Context, resourceType string) ([]role.RoleDescriptor, error) {
	return r.Repositories().RoleRepository().FindRolesByResourceType(ctx, resourceType)
}

// Assign assigns an identity ( users or organizations or teams or groups ) with a role, for a specific resource
// roleAssignments is a map of role assignments where the key is a role name and the value is an array of IDs of the identities
// which we want to assign the role to.
// If appendToExistingRoles == true then the new roles for these identities will be appended to the existing roles.
// If appendToExistingRoles == false then the new roles will replace the existing ones (the existing ones will be deleted).
// IMPORTANT: This is a transactional method, which manages its own transaction/s internally
func (r *roleManagementServiceImpl) Assign(ctx context.Context, assignedBy uuid.UUID, roleAssignments map[string][]uuid.UUID, resourceID string, appendToExistingRoles bool) error {
	// Lookup the resourceID and ensure the resource is valid
	rt, err := r.Repositories().ResourceRepository().Load(ctx, resourceID)
	if err != nil {
		return err
	}

	// check if the current user token belongs to a user who has the necessary privileges
	// for assigning roles to other users.
	permissionService := r.Services().PermissionService()
	err = permissionService.RequireScope(ctx, assignedBy, resourceID, authorization.ScopeForManagingRolesInResourceType(rt.Name))
	if err != nil {
		return err
	}

	// Valid all the roles and user identity IDs, and ensure each user has been previously assigned
	// privileges for the resource, otherwise the invitation workflow should be used instead
	assignments := make(map[uuid.UUID][]uuid.UUID)

	var existingRoleIDs []uuid.UUID

	roleIDByNameCache := make(map[string]uuid.UUID)
	for roleName, identityIDs := range roleAssignments {
		roleID, found := roleIDByNameCache[roleName] // Use local cache instead of looking up for every role used in the assignments
		if !found {
			roleRef, err := r.Repositories().RoleRepository().Lookup(ctx, roleName, rt.ResourceType.Name)
			if err != nil {
				return err
			}
			roleID = roleRef.RoleID
			roleIDByNameCache[roleName] = roleID
		}

		for _, identityIDAsUUID := range identityIDs {
			assignedRoles, err := r.Repositories().IdentityRoleRepository().FindIdentityRolesByIdentityAndResource(ctx, resourceID, identityIDAsUUID)
			if err != nil {
				log.Error(ctx, map[string]interface{}{
					"resource_id": resourceID,
					"identity_id": assignedBy,
				}, "error looking up existing assignments")
				return err
			}
			if len(assignedRoles) == 0 {
				log.Error(ctx, map[string]interface{}{
					"resource_id": resourceID,
					"identity_id": identityIDAsUUID,
				}, "identity not previously assigned a resource role cannot be assigned another role")
				return errors.NewBadParameterErrorFromString("identityID", identityIDAsUUID, fmt.Sprintf("cannot update roles for an identity %s without an existing role", identityIDAsUUID))
			}

			if ids, found := assignments[roleID]; found {
				assignments[roleID] = append(ids, identityIDAsUUID)
			} else {
				assignments[roleID] = []uuid.UUID{identityIDAsUUID}
			}
			for _, role := range assignedRoles {
				existingRoleIDs = append(existingRoleIDs, role.IdentityRoleID)
			}
		}
	}

	err = r.Transactional(func() error {
		// Now that we have confirmed that all users have pre-existing role assignments
		// we can proceed with the assignment of roles.

		if !appendToExistingRoles {
			// Delete all existing roles before creating the new ones
			deletedRoles := make(map[uuid.UUID]bool)
			for _, roleID := range existingRoleIDs {
				if _, found := deletedRoles[roleID]; !found { // Skip duplicated roles
					err = r.Repositories().IdentityRoleRepository().Delete(ctx, roleID)
					if err != nil {
						return err
					}
					deletedRoles[roleID] = true
				}
			}
		}

		for roleID, ids := range assignments {
			for _, identityIDAsUUID := range ids {
				ir := rolerepo.IdentityRole{
					ResourceID: resourceID,
					IdentityID: identityIDAsUUID,
					RoleID:     roleID,
				}

				err = r.Repositories().IdentityRoleRepository().Create(ctx, &ir)

				if err != nil {
					log.Error(ctx, map[string]interface{}{
						"resource_id": resourceID,
						"identity_id": identityIDAsUUID,
						"role_id":     roleID,
					}, "assignment failed")
					return err
				}
			}
		}

		return nil
	})

	return err
}
