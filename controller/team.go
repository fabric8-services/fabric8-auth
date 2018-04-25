package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/goadesign/goa"
)

// TeamController implements the team resource.
type TeamController struct {
	*goa.Controller
}

// NewTeamController creates a team controller.
func NewTeamController(service *goa.Service) *TeamController {
	return &TeamController{Controller: service.NewController("TeamController")}
}

// Create runs the create action.
func (c *TeamController) Create(ctx *app.CreateTeamContext) error {
	// TeamController_Create: start_implement

	// Put your logic here

	// TeamController_Create: end_implement
	return nil
}

// List runs the list action.
func (c *TeamController) List(ctx *app.ListTeamContext) error {
	// TeamController_List: start_implement

	// Put your logic here

	// TeamController_List: end_implement
	res := &app.OrganizationArray{}
	return ctx.OK(res)
}
