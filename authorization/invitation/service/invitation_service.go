package service

import (
	"context"
	"fmt"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/authorization/invitation"
	invitationrepo "github.com/fabric8-services/fabric8-auth/authorization/invitation/repository"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	"github.com/fabric8-services/fabric8-auth/errors"

	"strings"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	"github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/notification"
	"github.com/satori/go.uuid"
)

type InvitationConfiguration interface {
	GetAuthServiceURL() string
	IsPostgresDeveloperModeEnabled() bool
}

type invitationServiceImpl struct {
	base.BaseService
	config InvitationConfiguration
}

func NewInvitationService(context servicecontext.ServiceContext, config InvitationConfiguration) service.InvitationService {
	return &invitationServiceImpl{
		BaseService: base.NewBaseService(context),
		config:      config}
}

// Issue creates new invitations. The inviteTo parameter is the unique id of the organization, team, security group
// (the Identity ID) or resource (Resource ID) for which the invitations will be issued, and the invitations parameter
// contains the users and state for each individual user invitation.
// This method creates one record in the INVITATION table for each user in the invitations parameter.  Any roles that are issued
// as part of a user's invitation are created in the INVITATION_ROLE table.
// IMPORTANT: This is a transactional method, which manages its own transaction/s internally
func (s *invitationServiceImpl) Issue(ctx context.Context, issuingUserId uuid.UUID, inviteTo string, invitations []invitation.Invitation) error {
	var inviteToIdentity *account.Identity
	var identityResource *resource.Resource
	var inviteToResource *resource.Resource

	var notifications []invitationNotification

	err := s.ExecuteInTransaction(func() error {

		// First try to convert inviteTo to a uuid
		inviteToUUID, err := uuid.FromString(inviteTo)
		// If we get an error here, the value is definitely not for an Identity so we'll treat it as a resource ID
		if err != nil {
			// Try to lookup a resource with the same ID value
			inviteToResource, err = s.Repositories().ResourceRepository().Load(ctx, inviteTo)
			if err != nil {
				return errors.NewNotFoundError(fmt.Sprintf("invalid identifier '%s' provided for organization, team, security group or resource", inviteTo), inviteTo)
			}
		}

		// If we didn't successfully find a valid resource already, it means the inviteTo is a UUID
		if inviteToResource == nil {
			// Attempt to lookup the identity of the organization, team or security group that invitations will be issued for
			inviteToIdentity, err = s.Repositories().Identities().Load(ctx, inviteToUUID)
			if err != nil {
				// That didn't work, try to lookup a resource with the same ID value
				inviteToResource, err = s.Repositories().ResourceRepository().Load(ctx, inviteTo)
				if err != nil {
					return errors.NewNotFoundError(fmt.Sprintf("invalid identifier '%s' provided for organization, team, security group or resource", inviteTo), inviteTo)
				}
			}
		}

		// We currently only support:
		// 1) Invitation to a space
		// 2) Invitation to a team
		if inviteToIdentity != nil {
			identityResource, err := s.Repositories().ResourceRepository().Load(ctx, inviteToIdentity.IdentityResourceID.String)
			if err != nil {
				return err
			}

			if identityResource.ResourceType.Name != authorization.IdentityResourceTypeTeam {
				return errors.NewBadParameterErrorFromString("inviteTo", inviteTo, "Invitation is not for a team identity")
			}
		} else if inviteToResource != nil && inviteToResource.ResourceType.Name != authorization.ResourceTypeSpace {
			return errors.NewBadParameterErrorFromString("inviteTo", inviteTo, "Invitation is not for a space")
		}

		// Create the permission service
		permService := s.Services().PermissionService()

		if inviteToIdentity != nil {
			// Load the resource for the identity
			if !inviteToIdentity.IdentityResourceID.Valid {
				return errors.NewBadParameterErrorFromString("inviteTo", inviteTo, "specified identity has no resource")
			}

			identityResource, err = s.Repositories().ResourceRepository().Load(ctx, inviteToIdentity.IdentityResourceID.String)
			if err != nil {
				return errors.NewInternalError(ctx, err)
			}

			// Confirm that the issuing user has the necessary scope to manage members for the organization, team or security group
			err := permService.RequireScope(ctx, issuingUserId, inviteToIdentity.IdentityResourceID.String, authorization.ScopeForManagingRolesInResourceType(identityResource.ResourceType.Name))
			if err != nil {
				return err
			}

			// We only allow membership in some identity types - confirm that we are inviting to an organization, team or security group
			if !authorization.CanHaveMembers(identityResource.ResourceType.Name) {
				return errors.NewInternalErrorFromString(ctx, "may only invite a user as a member to an organization, team or security group")
			}
		} else if inviteToResource != nil {
			// Confirm that the issuing user has the manage members scope for the resource
			err := permService.RequireScope(ctx, issuingUserId, inviteToResource.ResourceID, authorization.ScopeForManagingRolesInResourceType(inviteToResource.ResourceType.Name))
			if err != nil {
				return err
			}
		}

		// Iterate through all of the invitations and confirm that for each one:
		// 1) a valid user has been specified via its Identity ID
		// 2) any roles specified are valid roles for the organization, team or security group
		// For each invitation, ensure that the IdentityID value can be found and set it
		// 3) create invitation records
		for _, invitation := range invitations {
			// Load the identity
			identity, err := s.Repositories().Identities().Load(ctx, *invitation.IdentityID)
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

			// Create the invitation records
			inv := new(invitationrepo.Invitation)
			inv.IdentityID = *invitation.IdentityID
			inv.Identity = *identity

			if inviteToIdentity != nil {
				inv.InviteTo = &inviteToIdentity.ID
				inv.Member = invitation.Member
			} else if inviteToResource != nil {
				inv.ResourceID = &inviteToResource.ResourceID
			}

			err = s.Repositories().InvitationRepository().Create(ctx, inv)
			if err != nil {
				return errors.NewInternalError(ctx, err)
			}

			// For each role in the invitation, lookup the role and add it to the invitation
			for _, roleName := range invitation.Roles {
				var resourceTypeName string
				if inviteToIdentity != nil {
					resourceTypeName = identityResource.ResourceType.Name
				} else if inviteToResource != nil {
					resourceTypeName = inviteToResource.ResourceType.Name
				}

				role, err := s.Repositories().RoleRepository().Lookup(ctx, roleName, resourceTypeName)

				if err != nil {
					return errors.NewBadParameterErrorFromString("Roles", roleName, fmt.Sprintf("no such role found for resource type %s", resourceTypeName))
				}

				err = s.Repositories().InvitationRepository().AddRole(ctx, inv.InvitationID, role.RoleID)
				if err != nil {
					return errors.NewInternalError(ctx, err)
				}
			}

			notifications = append(notifications, invitationNotification{
				invitation: inv,
				roles:      invitation.Roles,
			})
		}

		return nil
	})

	if err != nil {
		return err
	}

	// Lookup the identity record of the user doing the inviting
	inviter, err := s.Repositories().Identities().LoadWithUser(ctx, issuingUserId)

	if err != nil {
		return err
	}

	// Use the notification service to send invitation e-mails to the invited users, in a separate thread
	// Currently we only support sending notifications for two types of invitations;
	//
	// 1) Invite user to team, membership only, no organization
	// 2) Invite user to space, roles only, no organization
	//
	if inviteToIdentity != nil {
		identityResource, err := s.Repositories().ResourceRepository().Load(ctx, inviteToIdentity.IdentityResourceID.String)
		if err != nil {
			return err
		}

		if identityResource.ResourceType.Name == authorization.IdentityResourceTypeTeam {
			err = s.processTeamInviteNotifications(ctx, inviteToIdentity, inviter.User.FullName, notifications)
		}
	} else if inviteToResource != nil && inviteToResource.ResourceType.Name == authorization.ResourceTypeSpace {
		err = s.processSpaceInviteNotifications(ctx, inviteToResource, inviter.User.FullName, notifications)
	}

	if err != nil {
		return err
	}

	return nil
}

type invitationNotification struct {
	invitation *invitationrepo.Invitation
	roles      []string
}

// processTeamInviteNotifications sends an e-mail notification to a user.
func (s *invitationServiceImpl) processTeamInviteNotifications(ctx context.Context, team *account.Identity, inviterName string,
	notifications []invitationNotification) error {
	teamName := team.IdentityResource.Name

	var spaceName string

	// Every team *should* have a parent space, but we'll put this check here just in case
	if team.IdentityResource.ParentResourceID != nil {
		sp, err := s.Services().WITService().GetSpace(ctx, *team.IdentityResource.ParentResourceID)
		if err != nil {
			return err
		}
		spaceName = sp.Name
	}

	var messages []notification.Message

	for _, n := range notifications {
		acceptURL := fmt.Sprintf("%s/api/invitations/accept?code=%s", s.config.GetAuthServiceURL(), n.invitation.AcceptCode.String())

		messages = append(messages, notification.NewTeamInvitationEmail(n.invitation.Identity.ID.String(),
			teamName,
			inviterName,
			spaceName,
			acceptURL))
	}

	_, _, e := s.Services().NotificationService().SendMessagesAsync(ctx, messages)
	return e
}

// processSpaceInviteNotifications sends an e-mail notification to a user.
func (s *invitationServiceImpl) processSpaceInviteNotifications(ctx context.Context, space *resource.Resource,
	inviterName string, notifications []invitationNotification) error {
	sp, err := s.Services().WITService().GetSpace(ctx, space.ResourceID)
	if err != nil {
		return err
	}
	spaceName := sp.Name

	var messages []notification.Message

	for _, n := range notifications {
		acceptURL := fmt.Sprintf("%s/api/invitations/accept?code=%s", s.config.GetAuthServiceURL(), n.invitation.AcceptCode.String())

		messages = append(messages, notification.NewSpaceInvitationEmail(n.invitation.Identity.ID.String(),
			spaceName,
			inviterName,
			strings.Join(n.roles, ","),
			acceptURL))
	}

	_, _, e := s.Services().NotificationService().SendMessagesAsync(ctx, messages)
	return e
}

// Rescind revokes an invitation request
func (s *invitationServiceImpl) Rescind(ctx context.Context, rescindingUserID, invitationID uuid.UUID) error {
	// Locate the invitation
	inv, err := s.Repositories().InvitationRepository().Load(ctx, invitationID)
	if err != nil {
		return errors.NewNotFoundErrorFromString(fmt.Sprintf("invalid identifier '%s' provided for invitation", invitationID.String()))
	}

	// Create the permission service
	permService := s.Services().PermissionService()

	if inv.InviteTo != nil {
		// Lookup identity with InviteTo ID
		inviteToIdentity, err := s.Repositories().Identities().Load(ctx, *inv.InviteTo)
		if err != nil {
			return errors.NewNotFoundErrorFromString(fmt.Sprintf("invalid identifier '%s' provided for organization, team or security group", inv.InviteTo.String()))
		}

		if !inviteToIdentity.IdentityResourceID.Valid {
			return errors.NewNotFoundErrorFromString(fmt.Sprintf("specified identity '%s' has no resource", inv.InviteTo.String()))
		}

		identityResource, err := s.Repositories().ResourceRepository().Load(ctx, inviteToIdentity.IdentityResourceID.String)
		if err != nil {
			return errors.NewInternalError(ctx, err)
		}

		// Confirm that the rescinding user has the necessary scope to manage members for the organization, team or security group
		err = permService.RequireScope(ctx, rescindingUserID, inviteToIdentity.IdentityResourceID.String, authorization.ScopeForManagingRolesInResourceType(identityResource.ResourceType.Name))
		if err != nil {
			return err
		}
	} else if inv.ResourceID != nil {
		// Lookup a resource with the ResourceID value
		inviteToResource, err := s.Repositories().ResourceRepository().Load(ctx, *inv.ResourceID)
		if err != nil {
			return errors.NewNotFoundErrorFromString(fmt.Sprintf("invalid identifier '%s' provided for resource", *inv.ResourceID))
		}

		// Confirm that the rescinding user has the manage members scope for the resource
		err = permService.RequireScope(ctx, rescindingUserID, inviteToResource.ResourceID, authorization.ScopeForManagingRolesInResourceType(inviteToResource.ResourceType.Name))
		if err != nil {
			return err
		}
	}

	err = s.ExecuteInTransaction(func() error {
		// Delete the invitation
		return s.Repositories().InvitationRepository().Delete(ctx, invitationID)
	})
	return err
}

// Accept processes an invitation acceptance click, and returns the resource ID of the resource or identity resource which the invitation is for
func (s *invitationServiceImpl) Accept(ctx context.Context, currentIdentityID uuid.UUID, token uuid.UUID) (string, error) {
	var resourceID string

	// Locate the invitation
	inv, err := s.Repositories().InvitationRepository().FindByAcceptCode(ctx, currentIdentityID, token)

	if err != nil {
		return resourceID, err
	}

	// If this invitation is for an identity
	if inv.InviteTo != nil {
		inviteToIdentity, err := s.Repositories().Identities().Load(ctx, *inv.InviteTo)
		if err != nil {
			return resourceID, err
		}

		// If the invitation is for a membership, add a membership record
		if inv.Member {
			s.Repositories().Identities().AddMember(ctx, inviteToIdentity.ID, currentIdentityID)
		}

		roles, err := s.Repositories().InvitationRepository().ListRoles(ctx, inv.InvitationID)
		if err != nil {
			return resourceID, err
		}

		// If the invitation includes role assignments, assign them
		for _, role := range roles {
			ir := &repository.IdentityRole{
				IdentityID: currentIdentityID,
				RoleID:     role.RoleID,
				ResourceID: inviteToIdentity.IdentityResourceID.String,
			}

			err = s.Repositories().IdentityRoleRepository().Create(ctx, ir)
			if err != nil {
				return resourceID, err
			}
		}

		// Delete the invitation
		s.Repositories().InvitationRepository().Delete(ctx, inv.InvitationID)

		// Return the identity ID
		return inviteToIdentity.IdentityResourceID.String, nil

	} else if inv.ResourceID != nil {
		inviteToResource, err := s.Repositories().ResourceRepository().Load(ctx, *inv.ResourceID)
		if err != nil {
			return resourceID, err
		}

		roles, err := s.Repositories().InvitationRepository().ListRoles(ctx, inv.InvitationID)
		if err != nil {
			return resourceID, err
		}

		for _, role := range roles {
			ir := &repository.IdentityRole{
				IdentityID: currentIdentityID,
				RoleID:     role.RoleID,
				ResourceID: inviteToResource.ResourceID,
			}

			err = s.Repositories().IdentityRoleRepository().Create(ctx, ir)
			if err != nil {
				return resourceID, err
			}
		}

		// Delete the invitation
		s.Repositories().InvitationRepository().Delete(ctx, inv.InvitationID)

		// Return the resource ID
		return inviteToResource.ResourceID, nil
	}

	return "", nil
}
