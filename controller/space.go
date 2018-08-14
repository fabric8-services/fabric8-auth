package controller

import (
	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"

	"github.com/goadesign/goa"
)

// SpaceController implements the space resource.
type SpaceController struct {
	*goa.Controller
	app application.Application
}

// NewSpaceController creates a space controller.
func NewSpaceController(service *goa.Service, app application.Application) *SpaceController {
	return &SpaceController{Controller: service.NewController("SpaceController"), app: app}
}

// Create runs the create action.
func (c *SpaceController) Create(ctx *app.CreateSpaceContext) error {
	currentIdentity, err := login.LoadContextIdentityIfNotDeprovisioned(ctx, c.app)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	// Create AuthZ resource for the space as part of soft migration from deprecated OAuth Service AuthZ API to new OSIO AuthZ API
	err = c.app.SpaceService().CreateSpace(ctx, currentIdentity.ID, ctx.SpaceID.String())
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":      err,
			"space_id": ctx.SpaceID,
		}, "unable to register resource for space or assign space admin role to space creator")
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	return ctx.OK(&app.SpaceResource{Data: &app.SpaceResourceData{
		ResourceID: ctx.SpaceID.String(),
	}})
}

// Delete runs the delete action.
func (c *SpaceController) Delete(ctx *app.DeleteSpaceContext) error {
	currentIdentity, err := login.LoadContextIdentityIfNotDeprovisioned(ctx, c.app)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	err = c.app.SpaceService().DeleteSpace(ctx, currentIdentity.ID, ctx.SpaceID.String())
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":      err,
			"space_id": ctx.SpaceID,
		}, "unable to delete authZ space resource")
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	return ctx.OK([]byte{})
}

// ListTeams runs the listTeams action.
func (c *SpaceController) ListTeams(ctx *app.ListTeamsSpaceContext) error {
	currentUser, err := login.ContextIdentity(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError(err.Error()))
	}

	if currentUser == nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("error finding the current user"))
	}

	teams, err := c.app.TeamService().ListTeamsInSpace(ctx, *currentUser, ctx.SpaceID)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "failed to list teams")
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	return ctx.OK(&app.TeamArray{convertToTeamData(teams)})
}

func convertToTeamData(teams []account.Identity) []*app.TeamData {
	results := []*app.TeamData{}

	for _, team := range teams {
		teamData := &app.TeamData{
			ID:   team.ID.String(),
			Name: team.IdentityResource.Name,
		}

		results = append(results, teamData)
	}

	return results
}
