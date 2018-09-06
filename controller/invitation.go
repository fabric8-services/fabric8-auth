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

// CreateInvite runs the create action.
func (c *InvitationController) CreateInvite(ctx *app.CreateInviteInvitationContext) error {
	currentIdentity, err := login.LoadContextIdentityIfNotDeprovisioned(ctx, c.app)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	var redirectOnSuccess, redirectOnFailure string
	links := ctx.Payload.Links
	if links != nil {
		if links.OnSuccess != nil {
			redirectOnSuccess = *links.OnSuccess
		}
		if links.OnFailure != nil {
			redirectOnFailure = *links.OnFailure
		}
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
			IdentityID:        &identityID,
			Roles:             invitee.Roles,
			Member:            *invitee.Member,
			RedirectOnSuccess: redirectOnSuccess,
			RedirectOnFailure: redirectOnFailure,
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

// RescindInvite runs the revoke action.
func (c *InvitationController) RescindInvite(ctx *app.RescindInviteInvitationContext) error {
	currentIdentity, err := login.LoadContextIdentityIfNotDeprovisioned(ctx, c.app)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	invitationID, err := uuid.FromString(ctx.InviteTo)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":          err,
			"invitationID": invitationID,
		}, "failed to rescind invitation, invalid invitation id")

		return jsonapi.JSONErrorResponse(ctx, errors.NewNotFoundError("invitationID", invitationID.String()))
	}

	err = c.app.InvitationService().Rescind(ctx, currentIdentity.ID, invitationID)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":          err,
			"invitationID": invitationID,
		}, "failed to rescind invitation")
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	log.Debug(ctx, map[string]interface{}{
		"rescinding-user-id": *currentIdentity,
		"invitation-id":      ctx.InviteTo,
	}, "invitation rescind")

	return ctx.OK([]byte{})
}

func (c *InvitationController) AcceptInvite(ctx *app.AcceptInviteInvitationContext) error {
	redirectURL := c.config.GetInvitationAcceptedRedirectURL()

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

	_, invitationRedirectURL, err := c.app.InvitationService().Accept(ctx, acceptCode)

	if len(invitationRedirectURL) > 0 {
		redirectURL = invitationRedirectURL
	}

	if err != nil {
		errResponse := err.Error()
		redirectURL, err = rest.AddParam(redirectURL, "error", errResponse)
		if err != nil {
			return err
		}
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "failed to accept invitation")

		ctx.ResponseData.Header().Set("Location", redirectURL)
		return ctx.TemporaryRedirect()
	}

	log.Debug(ctx, map[string]interface{}{
		"accept-code": ctx.AcceptCode,
	}, "invitation accepted")

	ctx.ResponseData.Header().Set("Location", redirectURL)
	return ctx.TemporaryRedirect()
}
