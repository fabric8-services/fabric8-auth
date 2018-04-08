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
	CreateForGroup(ctx context.Context, issuingUserId uuid.UUID, inviteTo uuid.UUID, invitations []invitation.GroupInvitation) error
	CreateForResource(ctx context.Context, issuingUserId uuid.UUID, resourceId string, invitations []invitation.Invitation) error
	ListForGroup(ctx context.Context, id uuid.UUID) ([]invitation.GroupInvitation, error)
	ListForResource(ctx context.Context, resourceId string) ([]invitation.Invitation, error)
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

func (s *InvitationServiceImpl) CreateForGroup(ctx context.Context, issuingUserId uuid.UUID, inviteTo uuid.UUID, invitations []invitation.GroupInvitation) error {

	var err error

	err = application.Transactional(s.db, func(appl application.Application) error {
		err = s.invModelService.CreateForGroup(ctx, issuingUserId, inviteTo, invitations)
		return err
	})

	return err
}

func (s *InvitationServiceImpl) CreateForResource(ctx context.Context, issuingUserId uuid.UUID, resourceId string, invitations []invitation.Invitation) error {
	return nil
}

func (s *InvitationServiceImpl) ListForGroup(ctx context.Context, id uuid.UUID) ([]invitation.GroupInvitation, error) {
	return nil, nil
}

func (s *InvitationServiceImpl) ListForResource(ctx context.Context, resourceId string) ([]invitation.Invitation, error) {
	return nil, nil
}

func (s *InvitationServiceImpl) ListForUser(ctx context.Context, id uuid.UUID) ([]invitation.InvitationDetail, error) {
	return nil, nil
}
