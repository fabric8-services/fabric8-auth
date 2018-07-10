package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/authorization/invitation"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
)

// InvitationControllerConfiguration the Configuration for the InvitationController
type InvitationControllerConfiguration interface {
	GetInvitationAcceptedRedirectURL() string
}

// InvitationController implements the invitation resource.
type InvitationController struct {
	*goa.Controller
	app    application.Application
	config InvitationControllerConfiguration
}

// NewInvitationController creates a invitation controller.
func NewInvitationController(service *goa.Service, app application.Application, configuration InvitationControllerConfiguration) *InvitationController {
	return &InvitationController{
		Controller: service.NewController("InvitationController"),
		app:        app,
		config:     configuration,
	}
}

// Create runs the create action.
func (c *InvitationController) CreateInvite(ctx *app.CreateInviteInvitationContext) error {
	currentIdentity, err := login.LoadContextIdentityIfNotDeprovisioned(ctx, c.app)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	var invitations []invitation.Invitation

	for _, invitee := range ctx.Payload.Data {
		// Validate that an identifying parameter has been set
		if invitee.IdentityID == nil {
			return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterErrorFromString("user identifier", "", "no identifier provided"))
		}

		// If an identity ID has been provided for the user, convert it to a UUID here
		var identityID uuid.UUID
		if invitee.IdentityID != nil && *invitee.IdentityID != "" {
			identityID, err = uuid.FromString(*invitee.IdentityID)
		}

		// Create the Invitation object, and append it to our list of invitations
		invitations = append(invitations, invitation.Invitation{
			IdentityID: &identityID,
			Roles:      invitee.Roles,
			Member:     *invitee.Member,
		})
	}

	err = c.app.InvitationService().Issue(ctx, currentIdentity.ID, ctx.InviteTo, invitations)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "failed to create invitations")

		return jsonapi.JSONErrorResponse(ctx, err)
	}

	log.Debug(ctx, map[string]interface{}{
		"issuing-user-id": *currentIdentity,
		"invite-to":       ctx.InviteTo,
	}, "invitations created")

	return ctx.Created()
}

func (c *InvitationController) AcceptInvite(ctx *app.AcceptInviteInvitationContext) error {
	redirectURL := c.config.GetInvitationAcceptedRedirectURL()

	currentIdentity, err := login.LoadContextIdentityIfNotDeprovisioned(ctx, c.app)
	if err != nil {
		errResponse := err.Error()
		redirectURL, err = rest.AddParam(redirectURL, "error", errResponse)
		ctx.ResponseData.Header().Set("Location", redirectURL)
		return ctx.TemporaryRedirect()
	}

	acceptCode, err := uuid.FromString(ctx.AcceptCode)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "failed to accept invitation, invalid code")

		errResponse := err.Error()
		redirectURL, err = rest.AddParam(redirectURL, "error", errResponse)
		ctx.ResponseData.Header().Set("Location", redirectURL)
		return ctx.TemporaryRedirect()
	}

	_, err = c.app.InvitationService().Accept(ctx, currentIdentity.ID, acceptCode)

	if err != nil {
		errResponse := err.Error()
		redirectURL, err = rest.AddParam(redirectURL, "error", errResponse)
		if err != nil {
			return err
		}
	}

	log.Debug(ctx, map[string]interface{}{
		"accepting-user-id": *currentIdentity,
		"accept-code":       ctx.AcceptCode,
	}, "invitation accepted")

	ctx.ResponseData.Header().Set("Location", redirectURL)
	return ctx.TemporaryRedirect()
}
