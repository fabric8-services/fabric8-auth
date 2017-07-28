package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/goadesign/goa"
)

// ProviderController implements the provider resource.
type ProviderController struct {
	*goa.Controller
	db application.DB
}

// NewProviderController creates a provider controller.
func NewProviderController(service *goa.Service, db application.DB) *ProviderController {
	return &ProviderController{
		Controller: service.NewController("ProviderController"),
		db:         db,
	}
}

// Get runs the get action.
func (c *ProviderController) Get(ctx *app.GetProviderContext) error {
	// ProviderController_Get: start_implement

	// Put your logic here

	// ProviderController_Get: end_implement
	res := &app.AuthToken{}
	return ctx.OK(res)
}
