package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/token"

	"github.com/goadesign/goa"
)

// ResourceController implements the resource resource.
type ResourceController struct {
	*goa.Controller
	app          application.Application
	TokenManager token.Manager
}

// NewResourceController creates a resource controller.
func NewResourceController(service *goa.Service, app application.Application) *ResourceController {
	return &ResourceController{Controller: service.NewController("ResourceController"), app: app}
}

// Delete runs the delete action.
func (c *ResourceController) Delete(ctx *app.DeleteResourceContext) error {
	if !token.IsServiceAccount(ctx) {
		log.Error(ctx, map[string]interface{}{}, "Unable to delete resource. Not a service account")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("not a service account"))
	}

	svc := c.app.ResourceService()
	err := svc.Delete(ctx, ctx.ResourceID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": ctx.ResourceID,
		}, "unable to delete resource")
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	return ctx.NoContent()
}

// Read runs the read action.
func (c *ResourceController) Read(ctx *app.ReadResourceContext) error {

	if !token.IsServiceAccount(ctx) {
		log.Error(ctx, map[string]interface{}{}, "Unable to read resource. Not a service account")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("not a service account"))
	}

	svc := c.app.ResourceService()
	res, err := svc.Read(ctx, ctx.ResourceID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": ctx.ResourceID,
		}, "unable to read resource")
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	return ctx.OK(res)
}

// Register runs the register action.
func (c *ResourceController) Register(ctx *app.RegisterResourceContext) error {

	if !token.IsServiceAccount(ctx) {
		log.Error(ctx, map[string]interface{}{}, "Unable to register resource. Not a service account")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("not a service account"))
	}

	svc := c.app.ResourceService()
	res, err := svc.Register(ctx, ctx.Payload.Type, ctx.Payload.ResourceID, ctx.Payload.ParentResourceID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_type": ctx.Payload.Type,
		}, "unable to register resource")
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	return ctx.Created(&app.RegisterResourceResponse{ResourceID: &res.ResourceID})
}
