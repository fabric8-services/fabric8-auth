package model

import (
	"context"
	"fmt"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/authorization/invitation"
	invitationrepo "github.com/fabric8-services/fabric8-auth/authorization/invitation/repository"
	permission "github.com/fabric8-services/fabric8-auth/authorization/permission/model"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"

	"github.com/satori/go.uuid"
)

// repositories interface lets us avoid an import cycle
type repositories interface {
	Identities() account.IdentityRepository
	ResourceRepository() resource.ResourceRepository
	PermissionModelService() permission.PermissionService
	InvitationRepository() invitationrepo.InvitationRepository
	RoleRepository() role.RoleRepository
}

type InvitationModelService interface {
	Issue(ctx context.Context, issuingUserId uuid.UUID, inviteTo string, invitations []invitation.Invitation) error
}

type InvitationModelServiceImpl struct {
	repo repositories
}

func NewInvitationService(repositories repositories) InvitationModelService {
	return &InvitationModelServiceImpl{repo: repositories}
}

// Issue creates new invitations. The inviteTo parameter is the unique id of the organization, team, security group or resource for
// which the invitations will be issued, and the invitations parameter contains the users and state for each individual user invitation.
// This method creates one record in the INVITATION table for each user in the invitations parameter.  Any roles that are issued
// as part of a user's invitation are created in the INVITATION_ROLE table.
func (s *InvitationModelServiceImpl) Issue(ctx context.Context, issuingUserId uuid.UUID, inviteTo string, invitations []invitation.Invitation) error {
	var inviteToIdentity *account.Identity
	var identityResource *resource.Resource
	var inviteToResource *resource.Resource

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
		if inviteToIdentity.IdentityResourceID == nil {
			return errors.NewBadParameterErrorFromString("inviteTo", inviteTo, "specified identity has no resource")
		}

		identityResource, err = s.repo.ResourceRepository().Load(ctx, *inviteToIdentity.IdentityResourceID)
		if err != nil {
			return errors.NewInternalError(ctx, err)
		}

		// Confirm that the issuing user has the necessary scope to manage members for the organization, team or security group
		scope, err := s.repo.PermissionModelService().HasScope(ctx, issuingUserId, *inviteToIdentity.IdentityResourceID, authorization.ManageMembersScope)
		if err != nil {
			return errors.NewInternalError(ctx, err)
		}

		if !scope {
			return errors.NewForbiddenError(fmt.Sprintf("user requires %s scope to invite other users", authorization.ManageMembersScope))
		}

		// We only allow membership in some identity types - confirm that we are inviting to an organization, team or security group
		if !authorization.CanHaveMembers(identityResource.ResourceType.Name) {
			return errors.NewInternalErrorFromString(ctx, "may only invite a user as a member to an organization, team or security group")
		}
	} else if inviteToResource != nil {
		// Confirm that the issuing user has the manage members scope for the resource
		scope, err := s.repo.PermissionModelService().HasScope(ctx, issuingUserId, inviteToResource.ResourceID, authorization.ManageMembersScope)
		if err != nil {
			return errors.NewInternalError(ctx, err)
		}

		if !scope {
			return errors.NewForbiddenError(fmt.Sprintf("user requires %s scope to invite other users", authorization.ManageMembersScope))
		}
	}

	// Iterate through all of the invitations and confirm that for each one:
	// 1) a valid user has been specified via its Identity ID
	// 2) any roles specified are valid roles for the organization, team or security group
	// For each invitation, ensure that the IdentityID value can be found and set it
	for _, invitation := range invitations {
		// Load the identity
		identity, err := s.repo.Identities().Load(ctx, *invitation.IdentityID)
		if err != nil {
			return errors.NewInternalError(ctx, err)
		}

		if !identity.IsUser() {
			return errors.NewBadParameterErrorFromString("Identity ID", invitation.IdentityID, "identity is not a user")
		}

		if invitation.Member && inviteToResource != nil {
			// We cannot invite members to a resource, only certain identity types
			return errors.NewBadParameterErrorFromString("Member", invitation.IdentityID, "can not invite members to a resource")
		}
	}

	// Create the invitation records
	for _, invitation := range invitations {
		inv := new(invitationrepo.Invitation)
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
