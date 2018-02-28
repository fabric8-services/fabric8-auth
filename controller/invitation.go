package controller

import (
	invitationService "github.com/fabric8-services/fabric8-auth/authorization/invitation/service"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/goadesign/goa"
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

	ctx.InviteTo

	err := c.invService.CreateInvitations(ctx, *currentUser, *ctx.Payload.Members, *ctx.Payload.Roles)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":      err,
		}, "failed to create invitations")

		return jsonapi.JSONErrorResponse(ctx, err)
	}

	log.Debug(ctx, map[string]interface{}{
		"invite-to": ,
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
