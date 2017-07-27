package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/goadesign/goa"
)

// IdpController implements the idp resource.
type IdpController struct {
	*goa.Controller
}

// NewIdpController creates a idp controller.
func NewIdpController(service *goa.Service) *IdpController {
	return &IdpController{Controller: service.NewController("IdpController")}
}

// Get runs the get action.
func (c *IdpController) Get(ctx *app.GetIdpContext) error {
	// IdpController_Get: start_implement

	// Put your logic here

	// IdpController_Get: end_implement
	return nil
}

// Refresh runs the refresh action.
func (c *IdpController) Refresh(ctx *app.RefreshIdpContext) error {
	// IdpController_Refresh: start_implement

	// Put your logic here

	// IdpController_Refresh: end_implement
	res := &app.AuthToken{}
	return ctx.OK(res)
}
