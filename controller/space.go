package controller

import (
	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/application/transaction"
	"github.com/fabric8-services/fabric8-auth/auth"
	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/space"

	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
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
	app             application.Application
	config          SpaceConfiguration
	resourceManager auth.AuthzResourceManager
}

// NewSpaceController creates a space controller.
func NewSpaceController(service *goa.Service, app application.Application, config SpaceConfiguration, resourceManager auth.AuthzResourceManager) *SpaceController {
	return &SpaceController{Controller: service.NewController("SpaceController"), app: app, config: config, resourceManager: resourceManager}
}

// Create runs the create action.
func (c *SpaceController) Create(ctx *app.CreateSpaceContext) error {
	currentIdentity, err := login.LoadContextIdentityIfNotDeprovisioned(ctx, c.app)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	// Create keycloak resource for this space
	resource, err := c.resourceManager.CreateResource(ctx, ctx.RequestData, ctx.SpaceID.String(), spaceResourceType, nil, &scopes, currentIdentity.ID.String())
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	spaceResource := &space.Resource{
		ResourceID:   resource.ResourceID,
		PolicyID:     resource.PolicyID,
		PermissionID: resource.PermissionID,
		SpaceID:      ctx.SpaceID,
		OwnerID:      currentIdentity.ID,
	}

	err = transaction.Transactional(c.app, func(tr transaction.TransactionalResources) error {
		// Create space resource which will represent the keycloak resource associated with this space
		_, err = tr.SpaceResources().Create(ctx, spaceResource)
		return err
	})
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	// Create AuthZ resource for the space as part of soft migration from deprecated Keycloak AuthZ API to new OSIO AuthZ API
	spaceID := ctx.SpaceID.String()
	res, err := c.app.ResourceService().Register(ctx, authorization.ResourceTypeSpace, &spaceID, nil)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"space_id": ctx.SpaceID,
		}, "unable to register resource for space")
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	err = c.app.RoleManagementService().AssignAsAdmin(ctx, currentIdentity.ID, authorization.SpaceAdminRole, *res)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"space_id": ctx.SpaceID,
		}, "unable to assign space admin role to space creator")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}

	log.Debug(ctx, map[string]interface{}{
		"space_id":      ctx.SpaceID,
		"resource_id":   resource.ResourceID,
		"permission_id": resource.PermissionID,
		"policy_id":     resource.PolicyID,
	}, "space resource created")

	return ctx.OK(&app.SpaceResource{Data: &app.SpaceResourceData{
		ResourceID:   resource.ResourceID,
		PermissionID: resource.PermissionID,
		PolicyID:     resource.PolicyID,
	}})
}

// Delete runs the delete action.
func (c *SpaceController) Delete(ctx *app.DeleteSpaceContext) error {
	currentIdentity, err := login.LoadContextIdentityIfNotDeprovisioned(ctx, c.app)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	var resourceID string
	var permissionID string
	var policyID string
	err = transaction.Transactional(c.app, func(tr transaction.TransactionalResources) error {
		// Delete associated space resource
		resource, err := tr.SpaceResources().LoadBySpace(ctx, &ctx.SpaceID)
		if err != nil {
			return err
		}
		if !uuid.Equal(currentIdentity.ID, resource.OwnerID) {
			log.Warn(ctx, map[string]interface{}{
				"space_id":            ctx.SpaceID,
				"space_owner":         resource.OwnerID,
				"current_identity_id": currentIdentity.ID,
			}, "user is not the space owner")
			return errors.NewForbiddenError("user is not the space owner")
		}
		resourceID = resource.ResourceID
		permissionID = resource.PermissionID
		policyID = resource.PolicyID

		return tr.SpaceResources().Delete(ctx, resource.ID)
	})

	if err != nil {
		if notFound, _ := errors.IsNotFoundError(err); notFound {
			log.Warn(ctx, map[string]interface{}{
				"space_id":            ctx.SpaceID,
				"current_identity_id": currentIdentity.ID,
			}, "Space is not found. May happen if it's an old space. Ignore until WIT and Auth resource space DB is in sync")
			return ctx.OK([]byte{})
		}
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	err = c.resourceManager.DeleteResource(ctx, ctx.RequestData, auth.Resource{ResourceID: resourceID, PermissionID: permissionID, PolicyID: policyID})
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	// Try to delete AuthZ resource for the space as part of soft migration from deprecated Keycloak AuthZ API to new OSIO AuthZ API
	// Old spaces doesn't have any registered resources, so, we don't return an error if unable to find the corresponding resource
	svc := c.app.ResourceService()
	err = svc.Delete(ctx, ctx.SpaceID.String())
	if err != nil {
		if notFound, _ := errors.IsNotFoundError(err); notFound {
			log.Warn(ctx, map[string]interface{}{
				"space_id": ctx.SpaceID,
			}, "unable to delete authZ space resource: resource not found; that's OK for old spaces")
		} else {
			log.Error(ctx, map[string]interface{}{
				"space_id": ctx.SpaceID,
			}, "unable to delete authZ space resource")
			return jsonapi.JSONErrorResponse(ctx, err)
		}
	}

	return ctx.OK([]byte{})
}

// ListTeams runs the listTeams action.
func (c *SpaceController) ListTeams(ctx *app.ListTeamsSpaceContext) error {
	currentUser, err := login.ContextIdentity(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError(err.Error()))
	}

	if currentUser == nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("error finding the current user"))
	}

	teams, err := c.app.TeamService().ListTeamsInSpace(ctx, *currentUser, ctx.SpaceID)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "failed to list teams")
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	return ctx.OK(&app.TeamArray{convertToTeamData(teams)})
}

func convertToTeamData(teams []account.Identity) []*app.TeamData {
	results := []*app.TeamData{}

	for _, team := range teams {
		teamData := &app.TeamData{
			ID:   team.ID.String(),
			Name: team.IdentityResource.Name,
		}

		results = append(results, teamData)
	}

	return results
}
