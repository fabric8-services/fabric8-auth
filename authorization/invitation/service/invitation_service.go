package service

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/authorization/invitation"
	invitationModel "github.com/fabric8-services/fabric8-auth/authorization/invitation/model"
	permissionModel "github.com/fabric8-services/fabric8-auth/authorization/permission/model"
	uuid "github.com/satori/go.uuid"
)

type InvitationService interface {
	CreateInvitations(ctx context.Context, issuingUserId uuid.UUID, inviteTo uuid.UUID, invitations []invitation.Invitation) error
	ListInvitations(ctx context.Context, id uuid.UUID) ([]invitation.Invitation, error)
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

func (s *InvitationServiceImpl) CreateInvitations(ctx context.Context, issuingUserId uuid.UUID, inviteTo uuid.UUID, invitations []invitation.Invitation) error {

	var err error

	err = application.Transactional(s.db, func(appl application.Application) error {
		err = s.invModelService.CreateInvitations(ctx, issuingUserId, inviteTo, invitations)
		return err
	})

	return err
}

func (s *InvitationServiceImpl) ListInvitations(ctx context.Context, id uuid.UUID) ([]invitation.Invitation, error) {
	return nil, nil
}
