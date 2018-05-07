package service

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application/repository"
	"github.com/fabric8-services/fabric8-auth/application/transaction"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
	rolerepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/satori/go.uuid"
)

// RoleManagementService defines the service contract for managing role assignments
type RoleManagementService interface {
	ListByResource(ctx context.Context, resourceID string) ([]rolerepo.IdentityRole, error)
	ListAvailableRolesByResourceType(ctx context.Context, resourceType string) ([]role.RoleDescriptor, error)
	ListByResourceAndRoleName(ctx context.Context, resourceID string, roleName string) ([]rolerepo.IdentityRole, error)
	Assign(ctx context.Context, identityID uuid.UUID, resourceID string, roleName string) error
}

// NewRoleManagementService creates a new service to manage role assignments
func NewRoleManagementService(repo repository.Repositories) *RoleManagementServiceImpl {
	return &RoleManagementServiceImpl{repo: repo}
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

// Assign assigns an identity ( users or organizations or teams or groups ) with a role, for a specific resource
// IMPORTANT: This is a transactional method, which manages its own transaction/s internally
func (r *RoleManagementServiceImpl) Assign(ctx context.Context, identityID uuid.UUID, resourceID string, roleName string) error {

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
