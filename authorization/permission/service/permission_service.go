package service

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application"
	permissionModel "github.com/fabric8-services/fabric8-auth/authorization/permission/model"
	uuid "github.com/satori/go.uuid"
)

type PermissionService interface {
	HasScope(ctx context.Context, userID uuid.UUID, resourceID string, scope string) (bool, error)
}

type PermissionServiceImpl struct {
	modelService permissionModel.PermissionModelService
	db           application.DB
}

func NewPermissionService(modelService permissionModel.PermissionModelService, db application.DB) PermissionService {
	return &PermissionServiceImpl{modelService: modelService, db: db}
}

func (s *PermissionServiceImpl) HasScope(ctx context.Context, identityID uuid.UUID, resourceID string, scope string) (bool, error) {
	result := false
	err := application.Transactional(s.db, func(appl application.Application) error {
		hasScope, err := s.modelService.HasScope(ctx, identityID, resourceID, scope)
		if err == nil {
			result = hasScope
		}
		return err
	})
	return result, err
}
