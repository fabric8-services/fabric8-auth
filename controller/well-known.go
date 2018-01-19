package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/goadesign/goa"
)

// WellKnownController implements the .well-known resource.
type WellKnownController struct {
	*goa.Controller
}

// NewWellKnownController creates a .well-known controller.
func NewWellKnownController(service *goa.Service) *WellKnownController {
	return &WellKnownController{Controller: service.NewController("WellKnownController")}
}

// Show runs the show action.
func (c *WellKnownController) Show(ctx *app.ShowWellKnownContext) error {
	// WellKnownController_Show: start_implement

	// Put your logic here

	// WellKnownController_Show: end_implement
	res := &app.OpenIDConfiguration{}
	return ctx.OK(res)
}
