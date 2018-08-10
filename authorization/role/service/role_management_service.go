package service

import (
	"context"
	"fmt"

	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/authorization"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
	rolerepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/satori/go.uuid"
)

// NewRoleManagementService creates a new service to manage role assignments
func NewRoleManagementService(context servicecontext.ServiceContext) *roleManagementServiceImpl {
	return &roleManagementServiceImpl{base.NewBaseService(context)}
}

// RoleManagementServiceImpl implements the RoleManagementService to manage role assignments
type roleManagementServiceImpl struct {
	base.BaseService
}

// ListByResourceAndRoleName lists specific roles for the resource if the current user has permissions to view the roles
func (s *roleManagementServiceImpl) ListByResourceAndRoleName(ctx context.Context, currentIdentity uuid.UUID, resourceID string, roleName string) ([]rolerepo.IdentityRole, error) {
	err := s.requireViewRolesScope(ctx, currentIdentity, resourceID)
	if err != nil {
		return nil, err
	}

	return s.Repositories().IdentityRoleRepository().FindIdentityRolesByResourceAndRoleName(ctx, resourceID, roleName, false)
}

// ListByResource lists all identity roles for the resource if the current user has permissions to view the roles
func (s *roleManagementServiceImpl) ListByResource(ctx context.Context, currentIdentity uuid.UUID, resourceID string) ([]rolerepo.IdentityRole, error) {
	err := s.requireViewRolesScope(ctx, currentIdentity, resourceID)
	if err != nil {
		return nil, err
	}

	return s.Repositories().IdentityRoleRepository().FindIdentityRolesByResource(ctx, resourceID, false)
}

func (s *roleManagementServiceImpl) requireViewRolesScope(ctx context.Context, currentIdentity uuid.UUID, resourceID string) error {
	// Lookup the resourceID and ensure the resource is valid
	rt, err := s.Repositories().ResourceRepository().Load(ctx, resourceID)
	if err != nil {
		return err
	}

	// Check if the current user has the necessary privileges for viewing roles
	return s.Services().PermissionService().RequireScope(ctx, currentIdentity, resourceID, authorization.ScopeForViewingRolesInResourceType(rt.Name))
}

// ListAvailableRolesByResourceType lists role assignments of a specific resource.
func (s *roleManagementServiceImpl) ListAvailableRolesByResourceType(ctx context.Context, resourceType string) ([]role.RoleDescriptor, error) {
	return s.Repositories().RoleRepository().FindRolesByResourceType(ctx, resourceType)
}

// ListAvailableRolesByResourceTypeAndIdentity lists all roles on resources of a given type that are available for a given user (i.e, having a direct/inherited role in the resource)
func (s *roleManagementServiceImpl) ListAvailableRolesByResourceTypeAndIdentity(ctx context.Context, resourceType string, identityID uuid.UUID) ([]role.ResourceRoleDescriptor, error) {
	return s.Repositories().RoleRepository().FindRolesByResourceTypeAndIdentity(ctx, resourceType, identityID)
}

// Assign assigns an identity ( users or organizations or teams or groups ) with a role, for a specific resource.
// roleAssignments is a map of role assignments where the key is a role name and the value is an array of IDs of the identities
// which we want to assign the role to.
// If appendToExistingRoles == true then the new roles for these identities will be appended to the existing roles.
// If appendToExistingRoles == false then the new roles will replace the existing ones (the existing ones will be deleted).
// IMPORTANT: This is a transactional method, which manages its own transaction/s internally
func (s *roleManagementServiceImpl) Assign(ctx context.Context, assignedBy uuid.UUID, roleAssignments map[string][]uuid.UUID, resourceID string, appendToExistingRoles bool) error {
	// Lookup the resourceID and ensure the resource is valid
	rt, err := s.Repositories().ResourceRepository().Load(ctx, resourceID)
	if err != nil {
		return err
	}

	// check if the current user token belongs to a user who has the necessary privileges
	// for assigning roles to other users.
	permissionService := s.Services().PermissionService()
	err = permissionService.RequireScope(ctx, assignedBy, resourceID, authorization.ScopeForManagingRolesInResourceType(rt.Name))
	if err != nil {
		return err
	}

	// Valid all the roles and user identity IDs, and ensure each user has been previously assigned
	// privileges for the resource, otherwise the invitation workflow should be used instead
	assignments := make(map[uuid.UUID][]uuid.UUID)

	var existingRoleIDs []uuid.UUID

	roleIDByNameCache := make(map[string]uuid.UUID)
	checkedIdentityIDs := make(map[uuid.UUID]bool)
	for roleName, identityIDs := range roleAssignments {
		roleID, found := roleIDByNameCache[roleName] // Use local cache instead of looking up for every role used in the assignments
		if !found {
			roleRef, err := s.Repositories().RoleRepository().Lookup(ctx, roleName, rt.ResourceType.Name)
			if err != nil {
				return err
			}
			roleID = roleRef.RoleID
			roleIDByNameCache[roleName] = roleID
		}

		for _, identityIDAsUUID := range identityIDs {
			if found, _ := checkedIdentityIDs[identityIDAsUUID]; !found { // Don't check the same identity multiple times
				assignedRoles, err := s.Repositories().IdentityRoleRepository().FindIdentityRolesByIdentityAndResource(ctx, resourceID, identityIDAsUUID)
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
				for _, role := range assignedRoles {
					existingRoleIDs = append(existingRoleIDs, role.IdentityRoleID)
				}
				checkedIdentityIDs[identityIDAsUUID] = true
			}

			if ids, found := assignments[roleID]; found {
				assignments[roleID] = append(ids, identityIDAsUUID)
			} else {
				assignments[roleID] = []uuid.UUID{identityIDAsUUID}
			}
		}
	}

	err = s.ExecuteInTransaction(func() error {
		// Now that we have confirmed that all users have pre-existing role assignments
		// we can proceed with the assignment of roles.

		if !appendToExistingRoles {
			// Delete all existing roles before creating the new ones
			for _, roleID := range existingRoleIDs {
				err = s.Repositories().IdentityRoleRepository().Delete(ctx, roleID)
				if err != nil {
					return err
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

				err = s.Repositories().IdentityRoleRepository().Create(ctx, &ir)

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

// ForceAssign assigns an identity (users, organizations, teams or groups) with a role for a specific resource.
// This method doesn't check any permissions and assumes that the caller does all needed permissions checks.
// As an example: this method is to be used when creating a resource (space) to assign initial admin role to the resource creator.
// IMPORTANT: This is a transactional method, which manages its own transaction/s internally
func (s *roleManagementServiceImpl) ForceAssign(ctx context.Context, assignedTo uuid.UUID, roleName string, res resource.Resource) error {

	err := s.ExecuteInTransaction(func() error {
		role, err := s.Repositories().RoleRepository().Lookup(ctx, roleName, res.ResourceType.Name)
		if err != nil {
			return err
		}

		ir := rolerepo.IdentityRole{
			ResourceID: res.ResourceID,
			IdentityID: assignedTo,
			RoleID:     role.RoleID,
		}

		return s.Repositories().IdentityRoleRepository().Create(ctx, &ir)
	})

	return err
}

// RevokeResourceRoles revokes all roles for the resource for the specified identities
// IMPORTANT: This is a transactional method, which manages its own transaction/s internally
func (s *roleManagementServiceImpl) RevokeResourceRoles(ctx context.Context, currentIdentity uuid.UUID, identities []uuid.UUID, resourceID string) error {
	// Lookup the resourceID and ensure the resource is valid
	rt, err := s.Repositories().ResourceRepository().Load(ctx, resourceID)
	if err != nil {
		return err
	}

	// check if the current user token belongs to a user who has the necessary privileges
	// for managing roles.
	err = s.Services().PermissionService().RequireScope(ctx, currentIdentity, resourceID, authorization.ScopeForManagingRolesInResourceType(rt.Name))
	if err != nil {
		return err
	}

	err = s.ExecuteInTransaction(func() error {
		for _, identityID := range identities {
			err := s.Repositories().IdentityRoleRepository().DeleteForIdentityAndResource(ctx, resourceID, identityID)
			if err != nil {
				return err
			}
		}
		return nil
	})

	return err
}
