package model

import (
	"context"
	"fmt"
	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/authorization/invitation"
	permissionModel "github.com/fabric8-services/fabric8-auth/authorization/permission/model"
	"github.com/fabric8-services/fabric8-auth/authorization/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/jinzhu/gorm"
	uuid "github.com/satori/go.uuid"
)

type InvitationModelService interface {
	CreateInvitations(ctx context.Context, issuingUserId uuid.UUID, inviteTo uuid.UUID, invitations []invitation.Invitation) error
	ListInvitations(ctx context.Context, id uuid.UUID) ([]invitation.Invitation, error)
}

// GormInvitationModelService is the implementation of the interface for
// InvitationService. IMPORTANT NOTE: Transaction control is not provided by this service
type GormInvitationModelService struct {
	db           *gorm.DB
	repo         repository.Repositories
	permModelSvc permissionModel.PermissionModelService
}

// NewInvitationModelService creates a new service.
func NewInvitationModelService(db *gorm.DB, repo repository.Repositories, permissionSvc permissionModel.PermissionModelService) InvitationModelService {
	return &GormInvitationModelService{
		db:   db,
		repo: repo,
	}
}

// Creates new invitations.  The inviteTo parameter is the unique id of the organization, team or security group for
// which the invitations will be issued, and the invitations parameter contains the users,
func (s *GormInvitationModelService) CreateInvitations(ctx context.Context, issuingUserId uuid.UUID, inviteTo uuid.UUID,
	invitations []invitation.Invitation) error {

	// Lookup the identity resource of the organization, team or security group that invitations will be issued for
	inviteToIdentity, err := s.repo.Identities().Load(ctx, inviteTo)

	if err != nil {
		return errors.NewNotFoundError(fmt.Sprintf("invalid identifier provided for organization, team or security group\n", inviteTo), inviteTo.String())
	}

	res := inviteToIdentity.IdentityResource

	// Confirm that the issuing user has the "invite_users" scope for the organization, team or security group
	scope, err := s.permModelSvc.HasScope(ctx, issuingUserId, res.ResourceID, authorization.InviteUserScope)
	if err != nil {
		return errors.NewInternalError(ctx, err)
	}

	if !scope {
		return errors.NewForbiddenError(fmt.Sprintf("user requires %s scope to invite other users\n", authorization.InviteUserScope))
	}

	// We only allow membership in some identity types - confirm that we are inviting to an organization, team or security group
	if !inviteToIdentity.IsOrganization() && !inviteToIdentity.IsTeam() && !inviteToIdentity.IsGroup() {
		return errors.NewInternalErrorFromString(ctx, "may only invite a user to an organization, team or security group")
	}

	// Iterate through all of the invitations and confirm that for each one:
	// 1) a valid user has been specified via its User ID, e-mail address or username
	// 2) any roles specified are valid roles for the organization, team or security group
	for _, invitation := range invitations {
		// If the UserID has been provided, confirm it is valid and that the identity is a user
		if invitation.UserID != nil {
			identity, err := s.repo.Identities().Load(ctx, *invitation.UserID)
			if err != nil {
				return errors.NewInternalErrorFromString(ctx, fmt.Sprintf("invalid user ID specified: %s\n", invitation.UserID))
			}

			if !identity.IsUser() {
				return errors.NewInternalErrorFromString(ctx, fmt.Sprintf("identity with ID %s not a user", invitation.UserID))
			}

		}

		// If the username has been provided, confirm the user is valid and that the identity is a user, and set the UserID
		if invitation.UserName != nil {
			// TODO
		}

		// If the user's e-mail address has been provided, confirm the user is valid and that the identity is a user, and set the UserID
		if invitation.UserEmail != nil {
			// TODO
		}

		// TODO Confirm that any specified roles are valid for this resource type
	}

	// TODO Create the invitation records

	return nil
}

func (s *GormInvitationModelService) ListInvitations(ctx context.Context, id uuid.UUID) ([]invitation.Invitation, error) {
	return nil, nil
}
