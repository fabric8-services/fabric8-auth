package authorization

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/authorization/assignment"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
)

type RoleAssignmentService interface {
	ListByResource(ctx context.Context, resourceID string) ([]role.IdentityRole, error)
}

type RoleAssignmentServiceImpl struct {
	modelService assignment.RoleAssignmentModelService
	db           application.DB
}

func NewRoleAssignmentService(modelService assignment.RoleAssignmentModelService, db application.DB) *RoleAssignmentServiceImpl {
	return &RoleAssignmentServiceImpl{modelService: modelService, db: db}
}

func (r *RoleAssignmentServiceImpl) ListByResource(ctx context.Context, resourceID string) ([]role.IdentityRole, error) {

	var roles []role.IdentityRole
	var err error
	err = application.Transactional(r.db, func(appl application.Application) error {
		err = appl.ResourceRepository().CheckExists(ctx, resourceID)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"resource_id": resourceID,
			}, "does not exist")
			return errors.NewNotFoundError("resource_id", resourceID)
		}

		roles, err = r.modelService.ListByResource(ctx, resourceID)
		return err
	})

	return roles, err
}
