package service

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application/repository"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
	rolerepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
)

// RoleManagementService defines the service contract for managing role assignments
type RoleManagementService interface {
	ListByResource(ctx context.Context, resourceID string) ([]rolerepo.IdentityRole, error)
	ListAvailableRolesByResourceType(ctx context.Context, resourceType string) ([]role.RoleDescriptor, error)
	ListByResourceAndRoleName(ctx context.Context, resourceID string, roleName string) ([]rolerepo.IdentityRole, error)
}

// NewRoleManagementService creates a new service to manage role assignments
func NewRoleManagementService(repo repository.Repositories) *RoleManagementServiceImpl {
	return &RoleManagementServiceImpl{
		repo: repo,
	}
}

// RoleManagementServiceImpl implements the RoleManagementService to manage role assignments
type RoleManagementServiceImpl struct {
	repo repository.Repositories
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
