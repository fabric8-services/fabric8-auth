package service

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/authorization/invitation"
	invitationModel "github.com/fabric8-services/fabric8-auth/authorization/invitation/model"
	permissionModel "github.com/fabric8-services/fabric8-auth/authorization/permission/model"
	"github.com/satori/go.uuid"
)

type InvitationService interface {
	Issue(ctx context.Context, issuingUserId uuid.UUID, inviteTo string, invitations []invitation.Invitation) error
	List(ctx context.Context, id uuid.UUID) ([]invitation.Invitation, error)
	ListForUser(ctx context.Context, id uuid.UUID) ([]invitation.InvitationDetail, error)
}

type InvitationServiceImpl struct {
	invModelService  invitationModel.InvitationModelService
	permModelService permissionModel.PermissionModelService
	db               application.DB
}

func NewInvitationService(invitationModelService invitationModel.InvitationModelService,
	permissionModelService permissionModel.PermissionModelService, db application.DB) InvitationService {
	return &InvitationServiceImpl{invModelService: invitationModelService, permModelService: permissionModelService, db: db}
}

func (s *InvitationServiceImpl) Issue(ctx context.Context, issuingUserId uuid.UUID, inviteTo string, invitations []invitation.Invitation) error {

	var err error

	err = application.Transactional(s.db, func(appl application.Application) error {
		err = s.invModelService.Issue(ctx, issuingUserId, inviteTo, invitations)
		return err
	})

	return err
}

func (s *InvitationServiceImpl) List(ctx context.Context, id uuid.UUID) ([]invitation.Invitation, error) {
	return nil, nil
}

func (s *InvitationServiceImpl) ListForUser(ctx context.Context, id uuid.UUID) ([]invitation.InvitationDetail, error) {
	return nil, nil
}
