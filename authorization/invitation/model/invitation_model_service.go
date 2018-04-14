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
	resourceRepo "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/jinzhu/gorm"
	"github.com/satori/go.uuid"
)

type InvitationModelService interface {
	Issue(ctx context.Context, issuingUserId uuid.UUID, inviteTo string, invitations []invitation.Invitation) error
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

// Issue creates new invitations.  The inviteTo parameter is the unique id of the organization, team, security group or resource for
// which the invitations will be issued, and the invitations parameter contains the users and state for each individual user invitation.
// This method creates one record in the INVITATION table for each user in the invitations parameter.  Any roles that are issued
// as part of a user's invitation are created in the INVITATION_ROLE table.
func (s *GormInvitationModelService) Issue(ctx context.Context, issuingUserId uuid.UUID, inviteTo string,
	invitations []invitation.Invitation) error {

	var inviteToIdentity *account.Identity
	var identityResource *resourceRepo.Resource
	var inviteToResource *resourceRepo.Resource

	// First try to convert inviteTo to a uuid
	inviteToUUID, err := uuid.FromString(inviteTo)
	// If we get an error here, the value is definitely not for an Identity so we'll treat it as a resource ID
	if err != nil {
		// Try to lookup a resource with the same ID value
		inviteToResource, err = s.repo.ResourceRepository().Load(ctx, inviteTo)
		if err != nil {
			return errors.NewNotFoundError(fmt.Sprintf("invalid identifier '%s' provided for organization, team, security group or resource", inviteTo), inviteTo)
		}
	}

	// If we didn't successfully find a valid resource already, it means the inviteTo is a UUID
	if inviteToResource == nil {
		// Attempt to lookup the identity of the organization, team or security group that invitations will be issued for
		inviteToIdentity, err = s.repo.Identities().Load(ctx, inviteToUUID)
		if err != nil {
			// That didn't work, try to lookup a resource with the same ID value
			inviteToResource, err = s.repo.ResourceRepository().Load(ctx, inviteTo)
			if err != nil {
				return errors.NewNotFoundError(fmt.Sprintf("invalid identifier '%s' provided for organization, team, security group or resource", inviteTo), inviteTo)
			}
		}
	}

	if inviteToIdentity != nil {
		// Load the resource for the identity
		identityResource, err = s.repo.ResourceRepository().Load(ctx, *inviteToIdentity.IdentityResourceID)
		if err != nil {
			return errors.NewInternalErrorFromString(ctx, "error loading resource for identity")
		}

		// Confirm that the issuing user has the necessary scope to manage members for the organization, team or security group
		scope, err := s.permModelSvc.HasScope(ctx, issuingUserId, *inviteToIdentity.IdentityResourceID, authorization.ManageMembersScope)
		if err != nil {
			return errors.NewInternalError(ctx, err)
		}

		if !scope {
			return errors.NewForbiddenError(fmt.Sprintf("user requires %s scope to invite other users", authorization.ManageMembersScope))
		}

		// We only allow membership in some identity types - confirm that we are inviting to an organization, team or security group
		if !authorization.CanHaveMembers(identityResource.ResourceType.Name) {
			return errors.NewInternalErrorFromString(ctx, "may only invite a user to an organization, team or security group")
		}
	} else if inviteToResource != nil {
		// Confirm that the issuing user has the manage members scope for the resource
		scope, err := s.permModelSvc.HasScope(ctx, issuingUserId, inviteToResource.ResourceID, authorization.ManageMembersScope)
		if err != nil {
			return errors.NewInternalError(ctx, err)
		}

		if !scope {
			return errors.NewForbiddenError(fmt.Sprintf("user requires %s scope to invite other users", authorization.ManageMembersScope))
		}
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
				return errors.NewInternalErrorFromString(ctx, fmt.Sprintf("invalid identity ID specified: %s", invitation.IdentityID))
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
	}

	// Create the invitation records
	for _, invitation := range invitations {
		inv := new(invRepo.Invitation)
		inv.IdentityID = *invitation.IdentityID

		if inviteToIdentity != nil {
			inv.InviteTo = &inviteToIdentity.ID
			inv.Member = invitation.Member
		} else if inviteToResource != nil {
			inv.ResourceID = &inviteToResource.ResourceID
		}

		error := s.repo.InvitationRepository().Create(ctx, inv)
		if error != nil {
			return errors.NewInternalError(ctx, error)
		}

		// For each role in the invitation, lookup the role and add it to the invitation
		for _, roleName := range invitation.Roles {
			var resourceTypeName string
			if inviteToIdentity != nil {
				resourceTypeName = identityResource.ResourceType.Name
			} else if inviteToResource != nil {
				resourceTypeName = inviteToResource.ResourceType.Name
			}

			role, error := s.repo.RoleRepository().Lookup(ctx, roleName, resourceTypeName)

			if error != nil {
				return errors.NewBadParameterErrorFromString("Roles", roleName, fmt.Sprintf("no such role found for resource type %s", resourceTypeName))
			}

			error = s.repo.InvitationRepository().AddRole(ctx, inv.InvitationID, role.RoleID)
			if error != nil {
				return errors.NewInternalError(ctx, error)
			}
		}
	}

	return nil
}
