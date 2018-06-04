package service

import (
	"context"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/authorization"

	"github.com/satori/go.uuid"
)

// spaceService is the default implementation of SpaceService. It is a private struct and should only be instantiated
// via the NewSpaceService() function.
type spaceService struct {
	base.BaseService
}

// NewSpaceService creates a new space service.
func NewSpaceService(context *servicecontext.ServiceContext) service.SpaceService {
	return &spaceService{base.NewBaseService(context)}
}

// CreateSpace creates a new space. The specified spaceCreatorIdentityID is the user creating the space, and the spaceID is the identifier for the
// space resource. The space creator will be assigned with Admin role in the space.
// IMPORTANT: This is a transactional method, which manages its own transaction/s internally
func (s *spaceService) CreateSpace(ctx context.Context, spaceCreatorIdentityID uuid.UUID, spaceID string) error {

	err := s.ExecuteInTransaction(func() error {
		res, err := s.Services().ResourceService().Register(ctx, authorization.ResourceTypeSpace, &spaceID, nil)
		if err != nil {
			return err
		}

		return s.Services().RoleManagementService().ForceAssign(ctx, spaceCreatorIdentityID, authorization.SpaceAdminRole, *res)
	})

	return err
}

// DeleteSpace deletes the space.
// IMPORTANT: This is a transactional method, which manages its own transaction/s internally
func (s *spaceService) DeleteSpace(ctx context.Context, spaceID string) error {

	return s.ExecuteInTransaction(func() error {
		return s.Services().ResourceService().Delete(ctx, spaceID)
	})
}
