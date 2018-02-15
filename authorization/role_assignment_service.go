package authorization

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/authorization/model"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
)

type RoleAssignmentService interface {
	//Assign()
	ListByResource(ctx context.Context, resourceID string) ([]role.IdentityRole, error)
}

type RoleAssignmentServiceImpl struct {
	modelService model.RoleAssignmentModelService
	db           application.DB
}

func NewRoleAssignmentService(modelService model.RoleAssignmentModelService, db application.DB) *RoleAssignmentServiceImpl {
	return &RoleAssignmentServiceImpl{modelService: modelService, db: db}
}

func (r *RoleAssignmentServiceImpl) ListByResource(ctx context.Context, resourceID string) ([]role.IdentityRole, error) {

	var roles []role.IdentityRole
	var err error
	err = application.Transactional(r.db, func(appl application.Application) error {
		roles, err = r.modelService.ListByResource(ctx, resourceID)
		return err
	})

	return roles, err
}
