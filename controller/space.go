package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/auth"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/space"
	"github.com/goadesign/goa"
	uuid "github.com/satori/go.uuid"
)

const (
	spaceResourceType = "space"
)

var scopes = []string{"read:space", "admin:space"}

// SpaceConfiguration represents space configuration
type SpaceConfiguration interface {
	GetKeycloakEndpointAuthzResourceset(*goa.RequestData) (string, error)
	GetKeycloakEndpointToken(*goa.RequestData) (string, error)
	GetKeycloakEndpointClients(*goa.RequestData) (string, error)
	GetKeycloakEndpointAdmin(*goa.RequestData) (string, error)
	GetKeycloakClientID() string
	GetKeycloakSecret() string
}

// SpaceController implements the space resource.
type SpaceController struct {
	*goa.Controller
	db              application.DB
	config          SpaceConfiguration
	resourceManager auth.AuthzResourceManager
}

// NewSpaceController creates a space controller.
func NewSpaceController(service *goa.Service, db application.DB, config SpaceConfiguration, resourceManager auth.AuthzResourceManager) *SpaceController {
	return &SpaceController{Controller: service.NewController("SpaceController"), db: db, config: config, resourceManager: resourceManager}
}

// Create runs the create action.
func (c *SpaceController) Create(ctx *app.CreateSpaceContext) error {
	currentUser, err := login.ContextIdentity(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, goa.ErrUnauthorized(err.Error()))
	}

	// Create keycloak resource for this space
	resource, err := c.resourceManager.CreateResource(ctx, ctx.RequestData, ctx.SpaceID.String(), spaceResourceType, nil, &scopes, currentUser.String())
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	spaceResource := &space.Resource{
		ResourceID:   resource.ResourceID,
		PolicyID:     resource.PolicyID,
		PermissionID: resource.PermissionID,
		SpaceID:      ctx.SpaceID,
		OwnerID:      *currentUser,
	}

	err = application.Transactional(c.db, func(appl application.Application) error {
		// Create space resource which will represent the keyclok resource associated with this space
		_, err = appl.SpaceResources().Create(ctx, spaceResource)
		return err
	})
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	log.Debug(ctx, map[string]interface{}{
		"space_id":      ctx.SpaceID,
		"resource_id":   resource.ResourceID,
		"permission_id": resource.PermissionID,
		"policy_id":     resource.PolicyID,
	}, "space resource created")

	return ctx.OK(&app.SpaceResource{&app.SpaceResourceData{
		ResourceID:   resource.ResourceID,
		PermissionID: resource.PermissionID,
		PolicyID:     resource.PolicyID,
	}})
}

// Delete runs the delete action.
func (c *SpaceController) Delete(ctx *app.DeleteSpaceContext) error {
	currentUser, err := login.ContextIdentity(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, goa.ErrUnauthorized(err.Error()))
	}
	var resourceID string
	var permissionID string
	var policyID string
	err = application.Transactional(c.db, func(appl application.Application) error {
		// Delete associated space resource
		resource, err := appl.SpaceResources().LoadBySpace(ctx, &ctx.SpaceID)
		if err != nil {
			return err
		}
		if !uuid.Equal(*currentUser, resource.OwnerID) {
			log.Warn(ctx, map[string]interface{}{
				"space_id":     ctx.SpaceID,
				"space_owner":  resource.OwnerID,
				"current_user": *currentUser,
			}, "user is not the space owner")
			return errors.NewForbiddenError("user is not the space owner")
		}
		resourceID = resource.ResourceID
		permissionID = resource.PermissionID
		policyID = resource.PolicyID

		return appl.SpaceResources().Delete(ctx, resource.ID)
	})

	if err != nil {
		if notFound, _ := errors.IsNotFoundError(err); notFound {
			log.Warn(ctx, map[string]interface{}{
				"space_id":     ctx.SpaceID,
				"current_user": *currentUser,
			}, "Space is not found. May happen if it's an old space. Ignore until WIT and Auth resource space DB is in sync")
			return ctx.OK([]byte{})
		}
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	err = c.resourceManager.DeleteResource(ctx, ctx.RequestData, auth.Resource{ResourceID: resourceID, PermissionID: permissionID, PolicyID: policyID})
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	return ctx.OK([]byte{})
}
