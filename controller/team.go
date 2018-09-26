package controller

import (
	"strings"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/goadesign/goa"
)

// TeamController implements the team resource.
type TeamController struct {
	*goa.Controller
	app application.Application
}

// NewTeamController creates a team controller.
func NewTeamController(service *goa.Service, app application.Application) *TeamController {
	return &TeamController{Controller: service.NewController("TeamController"), app: app}
}

// Create runs the create action.
func (c *TeamController) Create(ctx *app.CreateTeamContext) error {
	currentUser, err := login.ContextIdentity(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError(err.Error()))
	}

	if ctx.Payload.Name == nil || len(strings.TrimSpace(*ctx.Payload.Name)) == 0 {
		log.Error(ctx, map[string]interface{}{}, "organization name cannot be empty")
		return jsonapi.JSONErrorResponse(ctx, goa.ErrBadRequest("organization name cannot be empty"))
	}

	teamID, err := c.app.TeamService().CreateTeam(ctx, *currentUser, *ctx.Payload.SpaceID, *ctx.Payload.Name)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":       err,
			"space_id":  *ctx.Payload.SpaceID,
			"team_name": *ctx.Payload.Name,
		}, "failed to create team")

		return jsonapi.JSONErrorResponse(ctx, err)
	}

	log.Debug(ctx, map[string]interface{}{
		"team_id": teamID.String(),
	}, "team created")

	teamIDStr := teamID.String()

	return ctx.Created(&app.CreateTeamResponse{&teamIDStr})
}

// List runs the list action.
func (c *TeamController) List(ctx *app.ListTeamContext) error {
	currentUser, err := login.ContextIdentity(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError(err.Error()))
	}

	if currentUser == nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("error finding the current user"))
	}

	teams, err := c.app.TeamService().ListTeamsForIdentity(ctx, *currentUser)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "failed to list teams")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}

	return ctx.OK(&app.IdentityTeamArray{convertToIdentityTeamData(teams)})
}

func convertToIdentityTeamData(teams []authorization.IdentityAssociation) []*app.IdentityTeamData {
	results := []*app.IdentityTeamData{}

	for _, team := range teams {
		teamData := &app.IdentityTeamData{
			ID:      team.IdentityID.String(),
			Name:    team.ResourceName,
			Member:  team.Member,
			Roles:   team.Roles,
			SpaceID: *team.ParentResourceID,
		}

		results = append(results, teamData)
	}

	return results
}
