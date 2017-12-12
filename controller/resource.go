package controller

import (
	"fmt"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/authorization/resource"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/token"

	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
)

// ResourceController implements the resource resource.
type ResourceController struct {
	*goa.Controller
	db           application.DB
	TokenManager token.Manager
}

// NewResourceController creates a resource controller.
func NewResourceController(service *goa.Service, db application.DB) *ResourceController {
	return &ResourceController{Controller: service.NewController("ResourceController"), db: db}
}

// Delete runs the delete action.
func (c *ResourceController) Delete(ctx *app.DeleteResourceContext) error {
	// TODO validate the PAT here

	return nil
}

// Read runs the read action.
func (c *ResourceController) Read(ctx *app.ReadResourceContext) error {
	// TODO validate the PAT here

	return nil
}

// Register runs the register action.
func (c *ResourceController) Register(ctx *app.RegisterResourceContext) error {

	if !token.IsServiceAccount(ctx) {
		jerrors, _ := jsonapi.ErrorToJSONAPIErrors(ctx, goa.ErrUnauthorized("Invalid Service Account"))
		return ctx.Unauthorized(jerrors)
	}

	var res *resource.Resource

	err := application.Transactional(c.db, func(appl application.Application) error {

		// Lookup or create the resource type
		resourceType, err := appl.ResourceTypeRepository().LookupOrCreate(ctx, ctx.Payload.Type)
		if err != nil {
			return err
		}

		// Lookup the parent resource if one has been specified
		var parentResource *resource.Resource

		if ctx.Payload.ParentResourceID != nil {
			parentResource, err = appl.ResourceRepository().Load(ctx, *ctx.Payload.ParentResourceID)
			if err != nil {
				log.Error(ctx, map[string]interface{}{
					"err":                err,
					"parent_resource_id": ctx.Payload.ParentResourceID,
				}, "Parent resource could not be found")

				return errors.NewBadParameterError("Invalid parent resource ID specified", err)
			}
		}
		// Extract the resource owner ID from the request
		resourceOwnerID, err := uuid.FromString(ctx.Payload.ResourceOwnerID)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"err":               err,
				"resource_owner_id": ctx.Payload.ResourceOwnerID,
			}, "Resource owner ID is not valid")

			return errors.NewConversionError(fmt.Sprintf("resource owner ID is not a valid UUID %v", err.Error()))
		}

		// Lookup the identity record of the resource owner
		identity, err := appl.Identities().Load(ctx, resourceOwnerID)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"err":               err,
				"resource_owner_id": resourceOwnerID,
			}, "Resource owner could not be found")

			return err
		}

		// Create the new resource instance
		res = &resource.Resource{
			ResourceID:     uuid.NewV4().String(),
			ParentResource: parentResource,
			Owner:          *identity,
			OwnerID:        identity.ID,
			ResourceType:   *resourceType,
			ResourceTypeID: resourceType.ResourceTypeID,
			Description:    *ctx.Payload.Description,
		}

		// Persist the resource
		return appl.ResourceRepository().Create(ctx, res)
	})

	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	var parentResourceID string
	if res.ParentResource != nil {
		parentResourceID = res.ParentResource.ResourceID
	} else {
		parentResourceID = ""
	}

	log.Debug(ctx, map[string]interface{}{
		"resource_id":        res.ResourceID,
		"parent_resource_id": parentResourceID,
		"owner_id":           res.Owner.ID,
		"resource_type":      res.ResourceType.Name,
		"description":        res.Description,
	}, "resource registered")

	return ctx.Created(&app.RegisterResource{ID: &res.ResourceID})
}

// Update runs the update action.
func (c *ResourceController) Update(ctx *app.UpdateResourceContext) error {
	// TODO validate the PAT here

	return nil
}
