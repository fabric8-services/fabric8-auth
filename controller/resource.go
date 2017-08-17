package controller

import (

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/goadesign/goa"
)

// ResourceController implements the resource resource.
type ResourceController struct {
	*goa.Controller
}

// NewResourceController creates a resource controller.
func NewResourceController(service *goa.Service) *ResourceController {
	return &ResourceController{Controller: service.NewController("ResourceController")}
}

// Delete runs the delete action.
func (c *ResourceController) Delete(ctx *app.DeleteResourceContext) error {
	// ResourceController_Delete: start_implement

	// Put your logic here

	// ResourceController_Delete: end_implement
	return nil
}

// List runs the list action.
func (c *ResourceController) List(ctx *app.ListResourceContext) error {
	// ResourceController_List: start_implement

	// Put your logic here

	// ResourceController_List: end_implement
	return nil
}

// Read runs the read action.
func (c *ResourceController) Read(ctx *app.ReadResourceContext) error {
	// ResourceController_Read: start_implement

	// Put your logic here

	// ResourceController_Read: end_implement
	return nil
}

// Register runs the register action.
func (c *ResourceController) Register(ctx *app.RegisterResourceContext) error {
	// ResourceController_Register: start_implement

	// Put your logic here

	// ResourceController_Register: end_implement
	return nil
}

// Update runs the update action.
func (c *ResourceController) Update(ctx *app.UpdateResourceContext) error {
	// ResourceController_Update: start_implement

	// Put your logic here

	// ResourceController_Update: end_implement
	return nil
}
