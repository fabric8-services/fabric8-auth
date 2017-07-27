package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/goadesign/goa"
)

// BrokerController implements the broker resource.
type BrokerController struct {
	*goa.Controller
}

// NewBrokerController creates a broker controller.
func NewBrokerController(service *goa.Service) *BrokerController {
	return &BrokerController{Controller: service.NewController("BrokerController")}
}

// Get runs the get action.
func (c *BrokerController) Get(ctx *app.GetBrokerContext) error {
	// BrokerController_Get: start_implement

	// Put your logic here

	// BrokerController_Get: end_implement
	return nil
}

// Refresh runs the refresh action.
func (c *BrokerController) Refresh(ctx *app.RefreshBrokerContext) error {
	// BrokerController_Refresh: start_implement

	// Put your logic here

	// BrokerController_Refresh: end_implement
	res := &app.AuthToken{}
	return ctx.OK(res)
}
