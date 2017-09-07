package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/authorization/resource"
	"github.com/fabric8-services/fabric8-auth/jsonapi"

	"github.com/goadesign/goa"
	uuid "github.com/satori/go.uuid"
)

// ResourceController implements the resource resource.
type ResourceController struct {
	*goa.Controller
	db              application.DB
}

// NewResourceController creates a resource controller.
func NewResourceController(service *goa.Service, db application.DB) *ResourceController {
	return &ResourceController{Controller: service.NewController("ResourceController"), db: db}
}

// Delete runs the delete action.
func (c *ResourceController) Delete(ctx *app.DeleteResourceContext) error {
	// ResourceController_Delete: start_implement

	// Put your logic here

	// ResourceController_Delete: end_implement
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

	// TODO validate the PAT here

	var res *resource.Resource

	err := application.Transactional(c.db, func(appl application.Application) error {

		// Lookup or create the resource type
		resourceType, err := appl.ResourceTypeRepository().LookupOrCreate(ctx, ctx.Payload.Name)
		if (err != nil) {
			return jsonapi.JSONErrorResponse(ctx, err)
		}

		// Lookup the parent resource if one has been specified
		var parentResource *resource.Resource
		if (ctx.Payload.ParentResourceID != nil) {
			parentResource, err = appl.ResourceRepository().Load(ctx, *ctx.Payload.ParentResourceID)

			if (err != nil) {
				return jsonapi.JSONErrorResponse(ctx, err)
			}
		}

		// TODO extract the owner identity from the PAT
		var identityID uuid.UUID

		identity, err := appl.Identities().Load(ctx, identityID)
		if (err != nil) {
			// TODO raise an error if the identity could not be determined
		}

		res = &resource.Resource{
			ResourceID:     uuid.NewV4().String(),
			ParentResource: parentResource, //ctx.Payload.ParentResourceID,
			Owner:          *identity,
			ResourceType:   *resourceType,
			Description:    *ctx.Payload.Description,
		}

		// Create the resource
		appl.ResourceRepository().Create(ctx, res)

		return err
	})


	if (err != nil) {
	  return jsonapi.JSONErrorResponse(ctx, err)
	}

	return ctx.Created(&app.RegisterResource{ID: &res.ResourceID})
}

// Update runs the update action.
func (c *ResourceController) Update(ctx *app.UpdateResourceContext) error {
	// ResourceController_Update: start_implement

	// Put your logic here

	// ResourceController_Update: end_implement
	return nil
}
