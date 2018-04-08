package model

import (
	"context"
	"fmt"
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/authorization/invitation"
	invRepo "github.com/fabric8-services/fabric8-auth/authorization/invitation/repository"
	permissionModel "github.com/fabric8-services/fabric8-auth/authorization/permission/model"
	"github.com/fabric8-services/fabric8-auth/authorization/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/jinzhu/gorm"
	"github.com/satori/go.uuid"
)

type InvitationModelService interface {
	CreateForGroup(ctx context.Context, issuingUserId uuid.UUID, inviteTo uuid.UUID, invitations []invitation.GroupInvitation) error
	CreateForResource(ctx context.Context, issuingUserId uuid.UUID, resourceId string, invitations []invitation.Invitation) error
	ListForGroup(ctx context.Context, id uuid.UUID) ([]invitation.GroupInvitation, error)
	ListForResource(ctx context.Context, resourceId string) ([]invitation.Invitation, error)
	ListForUser(ctx context.Context, id uuid.UUID) ([]invitation.InvitationDetail, error)
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
		db:           db,
		repo:         repo,
		permModelSvc: permissionSvc,
	}
}

// Creates new invitations.  The inviteTo parameter is the unique id of the organization, team or security group for
// which the invitations will be issued, and the invitations parameter contains the users,
func (s *GormInvitationModelService) CreateForGroup(ctx context.Context, issuingUserId uuid.UUID, inviteTo uuid.UUID,
	invitations []invitation.GroupInvitation) error {

	// Lookup the identity of the organization, team or security group that invitations will be issued for
	inviteToIdentity, err := s.repo.Identities().Load(ctx, inviteTo)

	if err != nil {
		return errors.NewNotFoundError(fmt.Sprintf("invalid identifier '%s' provided for organization, team or security group\n", inviteTo), inviteTo.String())
	}

	// Load the resource for the identity
	inviteToResource, err := s.repo.ResourceRepository().Load(ctx, *inviteToIdentity.IdentityResourceID)
	if err != nil {
		return errors.NewInternalErrorFromString(ctx, "Error loading resource for identity")
	}

	// Confirm that the issuing user has the "invite_users" scope for the organization, team or security group
	scope, err := s.permModelSvc.HasScope(ctx, issuingUserId, *inviteToIdentity.IdentityResourceID, authorization.InviteUserScope)
	if err != nil {
		return errors.NewInternalError(ctx, err)
	}

	if !scope {
		return errors.NewForbiddenError(fmt.Sprintf("user requires %s scope to invite other users\n", authorization.InviteUserScope))
	}

	// We only allow membership in some identity types - confirm that we are inviting to an organization, team or security group
	if inviteToResource.ResourceType.Name != authorization.IdentityResourceTypeOrganization &&
		inviteToResource.ResourceType.Name != authorization.IdentityResourceTypeTeam &&
		inviteToResource.ResourceType.Name != authorization.IdentityResourceTypeGroup {
		return errors.NewInternalErrorFromString(ctx, "may only invite a user to an organization, team or security group")
	}

	// Iterate through all of the invitations and confirm that for each one:
	// 1) a valid user has been specified via its User ID, e-mail address or username
	// 2) any roles specified are valid roles for the organization, team or security group
	// For each invitation, ensure that the IdentityID value can be found and set it
	for i, invitation := range invitations {
		// If the UserID has been provided, confirm it is valid and that the identity is a user
		if invitation.IdentityID != nil {
			identity, err := s.repo.Identities().Load(ctx, *invitation.IdentityID)
			if err != nil {
				return errors.NewInternalErrorFromString(ctx, fmt.Sprintf("invalid identity ID specified: %s\n", invitation.IdentityID))
			}

			if !identity.IsUser() {
				return errors.NewBadParameterErrorFromString("Identity ID", invitation.IdentityID, "identity is not a user")
			}
		} else if invitation.UserName != nil {
			// If the username has been provided, confirm the user is valid and that the identity is a user, and set the UserID
			identities, err := s.repo.Identities().Query(account.IdentityFilterByUsername(*invitation.UserName))
			if err != nil {
				return errors.NewInternalError(ctx, err)
			}
			// If there is anything other than 1 result found, we have a problem
			if len(identities) == 0 {
				// If no users are found, return an error
				return errors.NewBadParameterErrorFromString("Username", invitation.UserName, "username not found")
			} else if len(identities) > 1 {
				// If more than one user is found, return an error
				return errors.NewBadParameterErrorFromString("Username", invitation.UserName, "more than one user with same username found")
			}

			// Set the IdentityID to that of the identity found
			invitations[i].IdentityID = &identities[0].ID
		} else if invitation.UserEmail != nil {
			// If the user's e-mail address has been provided, confirm the user is valid and that the identity is a user, and set the UserID
			users, err := s.repo.Users().Query(account.UserFilterByEmail(*invitation.UserEmail))
			if err != nil {
				return errors.NewInternalError(ctx, err)
			}
			// We expect exactly 1 user to be found, if not we return an error
			if len(users) == 0 {
				return errors.NewBadParameterErrorFromString("E-mail", invitation.UserEmail, "user with e-mail address not found")
			} else if len(users) > 1 {
				return errors.NewBadParameterErrorFromString("E-mail", invitation.UserEmail, "more than one user with e-mail address found")
			}

			userID := &users[0].ID

			// Now that we have the user ID, we can lookup the identity ID
			identities, err := s.repo.Identities().Query(account.IdentityFilterByUserID(*userID))
			// If there is anything other than 1 result found, return an error
			if len(identities) == 0 {
				return errors.NewBadParameterErrorFromString("E-mail", invitation.UserEmail, "no identity found for user with e-mail address")
			} else if len(identities) > 1 {
				return errors.NewBadParameterErrorFromString("E-mail", invitation.UserEmail, "more than one identity found for user with e-mail address")
			}

			// Set the IdentityID to that of the identity found
			invitations[i].IdentityID = &identities[0].ID
		}

		// Confirm that any specified roles are valid for this resource type
		for _, roleName := range invitation.Roles {
			_, error := s.repo.RoleRepository().Lookup(ctx, roleName, inviteToResource.ResourceType.Name)

			if error != nil {
				return errors.NewBadParameterErrorFromString("Roles", roleName, fmt.Sprintf("no such role found for resource type %s", inviteToResource.ResourceType.Name))
			}
		}
	}

	// Create the invitation records
	for _, invitation := range invitations {
		inv := &invRepo.Invitation{
			InviteTo: inviteTo,
			UserID:   *invitation.IdentityID,
			Member:   invitation.Member,
		}

		error := s.repo.InvitationRepository().Create(ctx, inv)
		if error != nil {
			return errors.NewInternalError(ctx, error)
		}

		// For each role in the invitation, lookup the role and add it to the invitation
		for _, roleName := range invitation.Roles {
			role, error := s.repo.RoleRepository().Lookup(ctx, roleName, inviteToResource.ResourceType.Name)

			if error != nil {
				return errors.NewBadParameterErrorFromString("Roles", roleName, fmt.Sprintf("no such role found for resource type %s", inviteToResource.ResourceType.Name))
			}
			s.repo.InvitationRepository().AddRole(ctx, inv.InvitationID, role.RoleID)
		}
	}

	return nil
}

func (s *GormInvitationModelService) CreateForResource(ctx context.Context, issuingUserId uuid.UUID, resourceId string, invitations []invitation.Invitation) error {
	return nil
}

func (s *GormInvitationModelService) ListForGroup(ctx context.Context, id uuid.UUID) ([]invitation.GroupInvitation, error) {
	return nil, nil
}

func (s *GormInvitationModelService) ListForResource(ctx context.Context, resourceId string) ([]invitation.Invitation, error) {
	return nil, nil
}

func (s *GormInvitationModelService) ListForUser(ctx context.Context, id uuid.UUID) ([]invitation.InvitationDetail, error) {
	return nil, nil
}
