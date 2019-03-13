package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	rolerepository "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/satori/go.uuid"

	"github.com/goadesign/goa"
)

// ResourceRolesController implements the resource_roles resource.
type ResourceRolesController struct {
	*goa.Controller
	app application.Application
}

// NewResourceRolesController creates a resource_roles controller.
func NewResourceRolesController(service *goa.Service, app application.Application) *ResourceRolesController {
	return &ResourceRolesController{
		Controller: service.NewController("ResourceRolesController"),
		app:        app,
	}
}

// ListAssigned runs the list action.
func (c *ResourceRolesController) ListAssigned(ctx *app.ListAssignedResourceRolesContext) error {
	currentIdentity, err := c.app.UserService().LoadContextIdentityIfNotBanned(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	var roles []rolerepository.IdentityRole

	roles, err = c.app.RoleManagementService().ListByResource(ctx, currentIdentity.ID, ctx.ResourceID)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": ctx.ResourceID,
			"err":         err,
		}, "error retrieving list of roles for a specific resource")
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	roleList := convertIdentityRoleToAppRoles(roles)
	return ctx.OK(&app.Identityroles{
		Data: roleList,
	})
}

// ListAssignedByRoleName runs the list action.
func (c *ResourceRolesController) ListAssignedByRoleName(ctx *app.ListAssignedByRoleNameResourceRolesContext) error {
	currentIdentity, err := c.app.UserService().LoadContextIdentityIfNotBanned(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	var roles []rolerepository.IdentityRole

	roles, err = c.app.RoleManagementService().ListByResourceAndRoleName(ctx, currentIdentity.ID, ctx.ResourceID, ctx.RoleName)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": ctx.ResourceID,
			"role_name":   ctx.RoleName,
			"err":         err,
		}, "error retrieving list of roles for a specific resource and a specific role")
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	rolesList := convertIdentityRoleToAppRoles(roles)
	if len(rolesList) == 0 {
		return jsonapi.JSONErrorResponse(ctx, errors.NewNotFoundError("role", ctx.RoleName))
	}
	return ctx.OK(&app.Identityroles{
		Data: rolesList,
	})
}

// AssignRole assigns a specific role for a resource, to one or more identities.
func (c *ResourceRolesController) AssignRole(ctx *app.AssignRoleResourceRolesContext) error {
	currentIdentity, err := manager.ContextIdentity(ctx)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": ctx.ResourceID,
		}, "error getting identity information from token")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError(err.Error()))
	}

	roleAssignments := make(map[string][]uuid.UUID)
	for _, assignment := range ctx.Payload.Data {
		for _, id := range assignment.Ids {

			identityIDAsUUID, err := uuid.FromString(id)
			if err != nil {
				log.Error(ctx, map[string]interface{}{
					"resource_id": ctx.ResourceID,
					"identity_id": id,
					"role":        assignment.Role,
				}, "invalid identity ID")
				return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("ids", id).Expected("uuid"))
			}
			if ids, found := roleAssignments[assignment.Role]; found {
				roleAssignments[assignment.Role] = append(ids, identityIDAsUUID)
			} else {
				roleAssignments[assignment.Role] = []uuid.UUID{identityIDAsUUID}
			}
		}
	}
	err = c.app.RoleManagementService().Assign(ctx, *currentIdentity, roleAssignments, ctx.ResourceID, false)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	return ctx.NoContent()
}

// HasScope checks if the user has the given scope in the requested resource
func (c *ResourceRolesController) HasScope(ctx *app.HasScopeResourceRolesContext) error {
	// retrieve the current user's identity from the request token
	currentIdentity, err := manager.ContextIdentity(ctx)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": ctx.ResourceID,
		}, "error getting identity information from token")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError(err.Error()))
	}
	// check that the resource exists
	if err := c.app.ResourceService().CheckExists(ctx, ctx.ResourceID); err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	//
	r, err := c.app.PermissionService().HasScope(ctx, *currentIdentity, ctx.ResourceID, ctx.ScopeName)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": ctx.ResourceID,
			"scope_name":  ctx.ScopeName,
			"err":         err,
		}, "error checking if the user has the given scope in the requested resource")
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	return ctx.OK(&app.IdentityResourceScope{
		Data: &app.IdentityResourceScopeData{
			ScopeName: ctx.ScopeName,
			HasScope:  r,
		},
	})
}

func convertIdentityRoleToAppRoles(roles []rolerepository.IdentityRole) []*app.IdentityRolesData {
	var rolesList []*app.IdentityRolesData
	for _, r := range roles {
		rolesList = append(rolesList, convertIdentityRoleToAppRole(r))
	}
	return rolesList
}

func convertIdentityRoleToAppRole(r rolerepository.IdentityRole) *app.IdentityRolesData {
	inherited := r.Resource.ParentResourceID != nil
	rolesData := app.IdentityRolesData{
		AssigneeID:   r.Identity.ID.String(),
		AssigneeType: "user", // will change for teams/orgs/groups
		Inherited:    inherited,
		RoleName:     r.Role.Name,
	}
	if inherited {
		rolesData.InheritedFrom = r.Resource.ParentResourceID
	}
	return &rolesData
}
