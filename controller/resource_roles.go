package controller

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/goadesign/goa"
)

// ResourceRolesController implements the resource_roles resource.
type ResourceRolesController struct {
	*goa.Controller
	db application.DB
}

// NewResourceRolesController creates a resource_roles controller.
func NewResourceRolesController(service *goa.Service, db application.DB) *ResourceRolesController {
	return &ResourceRolesController{
		Controller: service.NewController("ResourceRolesController"),
		db:         db,
	}
}

// ListAssigned runs the list action.
func (c *ResourceRolesController) ListAssigned(ctx *app.ListAssignedResourceRolesContext) error {

	var roles []role.IdentityRole

	err := application.Transactional(c.db, func(appl application.Application) error {
		var error error
		roles, error = appl.RoleManagementService().ListByResource(ctx, ctx.ResourceID)
		if error != nil {
			log.Error(ctx, map[string]interface{}{
				"resource_id": ctx.ResourceID,
				"err":         error,
			}, "error retrieving list of roles for a specific resource")
		}
		return error
	})

	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	roleList := convertIdentityRoleToAppRoles(ctx, roles)
	return ctx.OK(&app.Identityroles{
		Data: roleList,
	})
}

// ListAssignedByRoleName runs the list action.
func (c *ResourceRolesController) ListAssignedByRoleName(ctx *app.ListAssignedByRoleNameResourceRolesContext) error {

	var roles []role.IdentityRole

	err := application.Transactional(c.db, func(appl application.Application) error {
		var error error
		roles, error = appl.RoleManagementService().ListByResourceAndRoleName(ctx, ctx.ResourceID, ctx.RoleName)
		if error != nil {
			log.Error(ctx, map[string]interface{}{
				"resource_id": ctx.ResourceID,
				"err":         error,
			}, "error retrieving list of roles for a specific resource and a specific role")
		}
		return error
	})

	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	rolesList := convertIdentityRoleToAppRoles(ctx, roles)
	if len(rolesList) == 0 {
		return jsonapi.JSONErrorResponse(ctx, errors.NewNotFoundError("role", ctx.RoleName))
	}
	return ctx.OK(&app.Identityroles{
		Data: rolesList,
	})
}

func convertIdentityRoleToAppRoles(ctx context.Context, roles []role.IdentityRole) []*app.IdentityRolesData {
	var rolesList []*app.IdentityRolesData
	for _, r := range roles {
		rolesList = append(rolesList, convertIdentityRoleToAppRole(ctx, r))
	}
	return rolesList
}
func convertIdentityRoleToAppRole(ctx context.Context, r role.IdentityRole) *app.IdentityRolesData {
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
