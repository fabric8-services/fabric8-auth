package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourceType "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/token"

	"github.com/fabric8-services/fabric8-auth/application/transaction"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
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

	err := transaction.Transactional(c.app, func(tr transaction.TransactionalResources) error {

		// Delete the resource
		error := tr.ResourceRepository().Delete(ctx, ctx.ResourceID)

		log.Debug(ctx, map[string]interface{}{
			"resource_id": ctx.ResourceID,
		}, "Deleted resource.")

		return error
	})

	if err != nil {
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

	var res *resource.Resource
	var scopes []resourceType.ResourceTypeScope

	err := transaction.Transactional(c.app, func(tr transaction.TransactionalResources) error {

		var error error
		// Load the resource
		res, error = tr.ResourceRepository().Load(ctx, ctx.ResourceID)

		if error != nil {
			return error
		}

		// Load the resource type scopes
		scopes, error = tr.ResourceTypeScopeRepository().LookupForType(ctx, res.ResourceTypeID)

		return error
	})

	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	var scopeValues []string

	for index := range scopes {
		scopeValues = append(scopeValues, scopes[index].Name)
	}

	return ctx.OK(&app.Resource{
		ResourceID:       &res.ResourceID,
		Type:             res.ResourceType.Name,
		Name:             res.Name,
		ParentResourceID: res.ParentResourceID,
		ResourceScopes:   scopeValues,
	})
}

// Register runs the register action.
func (c *ResourceController) Register(ctx *app.RegisterResourceContext) error {

	if !token.IsServiceAccount(ctx) {
		log.Error(ctx, map[string]interface{}{}, "Unable to register resource. Not a service account")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("not a service account"))
	}

	var res *resource.Resource

	err := transaction.Transactional(c.app, func(tr transaction.TransactionalResources) error {

		// Lookup the resource type
		resourceType, err := tr.ResourceTypeRepository().Lookup(ctx, ctx.Payload.Type)
		if err != nil {
			return errors.NewBadParameterError("type", ctx.Payload.Type)
		}

		// Lookup the parent resource if one has been specified
		var parentResource *resource.Resource

		if ctx.Payload.ParentResourceID != nil {

			parentResource, err = tr.ResourceRepository().Load(ctx, *ctx.Payload.ParentResourceID)
			if err != nil {
				log.Error(ctx, map[string]interface{}{
					"err":                err,
					"parent_resource_id": ctx.Payload.ParentResourceID,
				}, "Parent resource could not be found.")

				return errors.NewBadParameterError("invalid parent resource ID specified", err)
			}
		}

		var resourceID string
		if ctx.Payload.ResourceID != nil {
			resourceID = *ctx.Payload.ResourceID
		} else {
			resourceID = uuid.NewV4().String()
		}

		var parentResourceID *string

		if parentResource != nil {
			parentResourceID = &parentResource.ResourceID
		}

		// Create the new resource instance
		res = &resource.Resource{
			ResourceID:       resourceID,
			Name:             ctx.Payload.Name,
			ParentResourceID: parentResourceID,
			ResourceType:     *resourceType,
			ResourceTypeID:   resourceType.ResourceTypeID,
		}

		// Persist the resource
		return tr.ResourceRepository().Create(ctx, res)
	})

	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	var parentResourceID string
	if res.ParentResourceID != nil {
		parentResourceID = *res.ParentResourceID
	} else {
		parentResourceID = ""
	}

	log.Debug(ctx, map[string]interface{}{
		"resource_id":        res.ResourceID,
		"parent_resource_id": parentResourceID,
		"resource_type":      res.ResourceType.Name,
	}, "resource registered")

	return ctx.Created(&app.RegisterResource{ID: &res.ResourceID})
}

// Update runs the update action.
func (c *ResourceController) Update(ctx *app.UpdateResourceContext) error {

	if !token.IsServiceAccount(ctx) {
		log.Error(ctx, map[string]interface{}{}, "Unable to register resource. Not a service account")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("not a service account"))
	}

	var res *resource.Resource

	err := transaction.Transactional(c.app, func(tr transaction.TransactionalResources) error {
		var error error
		res, error = tr.ResourceRepository().Load(ctx, ctx.ResourceID)
		if error != nil {
			return error
		}

		// If a name attribute has been passed in, update the resource name
		if ctx.Payload.Name != nil {
			res.Name = *ctx.Payload.Name
		}

		// If a type attribute has been passed in, update the resource type
		if ctx.Payload.Type != nil {
			resourceType, err := tr.ResourceTypeRepository().Lookup(ctx, *ctx.Payload.Type)
			if err != nil {
				return errors.NewBadParameterError("type", ctx.Payload.Type)
			}
			res.ResourceTypeID = resourceType.ResourceTypeID
		}

		// If a parent resource ID has been passed in, update the parent resource
		if ctx.Payload.ParentResourceID != nil {
			if *ctx.Payload.ParentResourceID != "" {
				// If a parent ID has been specified, lookup the parent resource
				parentResource, err := tr.ResourceRepository().Load(ctx, *ctx.Payload.ParentResourceID)
				if err != nil {
					log.Error(ctx, map[string]interface{}{
						"err":                err,
						"parent_resource_id": *ctx.Payload.ParentResourceID,
					}, "Parent resource could not be found.")

					return errors.NewBadParameterError("invalid parent resource ID specified", err)
				}

				res.ParentResourceID = &parentResource.ResourceID
			} else {
				res.ParentResourceID = nil
			}

		}

		return tr.ResourceRepository().Save(ctx, res)
	})

	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	return ctx.OK(&app.RegisterResource{ID: &res.ResourceID})
}
