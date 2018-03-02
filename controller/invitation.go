package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/authorization/invitation"
	invitationService "github.com/fabric8-services/fabric8-auth/authorization/invitation/service"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
)

// InvitationController implements the invitation resource.
type InvitationController struct {
	*goa.Controller
	invService invitationService.InvitationService
}

// NewInvitationController creates a invitation controller.
func NewInvitationController(service *goa.Service, invitationService invitationService.InvitationService) *InvitationController {
	return &InvitationController{Controller: service.NewController("InvitationController"), invService: invitationService}
}

// Create runs the create action.
func (c *InvitationController) Create(ctx *app.CreateInvitationContext) error {
	currentUser, err := login.ContextIdentity(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError(err.Error()))
	}

	if currentUser == nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("error finding the current user"))
	}

	inviteTo, err := uuid.FromString(ctx.InviteTo)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterErrorFromString("InviteTo", inviteTo, "Not a valid UUID"))
	}

	var invitations []invitation.Invitation

	for _, invitee := range ctx.Payload.Invitees {
		// Validate that an identifying parameter has been set
		if invitee.IdentityID == nil && invitee.Username == nil && invitee.UserEmail == nil {
			return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterErrorFromString("user identifier", "", "no identifier provided"))
		}

		// If an identity ID has been provided for the user, convert it to a UUID here
		var identityID uuid.UUID
		if invitee.IdentityID != nil {
			identityID, err = uuid.FromString(*invitee.IdentityID)
		}

		// Create the Invitation object, and append it to our list of invitations
		invitations = append(invitations, invitation.Invitation{
			IdentityID: &identityID,
			UserName:   invitee.Username,
			UserEmail:  invitee.UserEmail,
			Member:     *invitee.Member,
			Roles:      invitee.Roles})
	}

	err = c.invService.CreateInvitations(ctx, *currentUser, inviteTo, invitations)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "failed to create invitations")

		return jsonapi.JSONErrorResponse(ctx, err)
	}

	log.Debug(ctx, map[string]interface{}{
		"issuing-user-id": *currentUser,
		"invite-to":       inviteTo,
	}, "invitations created")

	return ctx.Created()
}

// List runs the list action.
func (c *InvitationController) List(ctx *app.ListInvitationContext) error {
	// InvitationController_List: start_implement

	// Put your logic here

	// InvitationController_List: end_implement
	return nil
}
