package service

import (
	"context"

	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/authorization/invitation"
	invitationModel "github.com/fabric8-services/fabric8-auth/authorization/invitation/model"
	"github.com/satori/go.uuid"
)

type InvitationService interface {
	Issue(ctx context.Context, issuingUserId uuid.UUID, inviteTo string, invitations []invitation.Invitation) error
}

type InvitationServiceImpl struct {
	invModelService invitationModel.InvitationModelService
	db              application.DB
}

func NewInvitationService(invitationModelService invitationModel.InvitationModelService, db application.DB) InvitationService {
	return &InvitationServiceImpl{invModelService: invitationModelService, db: db}
}

func (s *InvitationServiceImpl) Issue(ctx context.Context, issuingUserId uuid.UUID, inviteTo string, invitations []invitation.Invitation) error {

	var err error

	err = application.Transactional(s.db, func(appl application.Application) error {
		err = s.invModelService.Issue(ctx, appl, issuingUserId, inviteTo, invitations)
		return err
	})

	// TODO send e-mails to invited users with links to accept the invitations

	return err
}
