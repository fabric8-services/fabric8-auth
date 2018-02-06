package controller

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/goadesign/goa"
)

// ResourceRolesController implements the resource_roles resource.
type ResourceRolesController struct {
	*goa.Controller
	db           application.DB
	TokenManager token.Manager
}

// NewResourceRolesController creates a resource_roles controller.
func NewResourceRolesController(service *goa.Service) *ResourceRolesController {
	return &ResourceRolesController{Controller: service.NewController("ResourceRolesController")}
}

// ListAssigned runs the list action.
func (c *ResourceRolesController) ListAssigned(ctx *app.ListAssignedResourceRolesContext) error {
	var roles []role.Role
	err := application.Transactional(c.db, func(appl application.Application) error {
		resourceExists, err := appl.RoleRepository().CheckExists(ctx, ctx.ID)
		if err != nil {
			return err
		}
		if !resourceExists {
			return errors.NewNotFoundError("resource", ctx.ID)
		}
		roles, err = appl.RoleRepository().ListByResource(ctx, ctx.ID)
		if err != nil {
			return err
		}
		log.Debug(ctx, map[string]interface{}{
			"resource_id": ctx.ID,
		}, "Fetched roles by resource.")

		return err
	})
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": ctx.ID,
			"err":         err,
		}, "error retrieving list of roles for a specific resource")
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	roleList := convertToAppRoles(ctx, roles)
	return ctx.OK(&app.Roles{
		Data: roleList,
	})
}

// ListAssigned runs the list action.
func (c *ResourceRolesController) List(ctx *app.ListResourceRolesContext) error {
	var roles []role.Role
	err := application.Transactional(c.db, func(appl application.Application) error {
		resourceExists, err := appl.RoleRepository().CheckExists(ctx, ctx.ID)
		if err != nil {
			return err
		}
		if !resourceExists {
			return errors.NewNotFoundError("resource", ctx.ID)
		}
		roles, err = appl.RoleRepository().ListByResource(ctx, ctx.ID)
		if err != nil {
			return err
		}
		log.Debug(ctx, map[string]interface{}{
			"resource_id": ctx.ID,
		}, "Fetched roles by resource.")

		return err
	})
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": ctx.ID,
			"err":         err,
		}, "error retrieving list of roles for a specific resource")
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	roleList := convertRoleToAppRoles(ctx, roles)
	return ctx.OK(&app.Roles{
		Data: roleList,
	})
}

func convertRoleToAppRoles(ctx context.Context, roles []role.Role) []*app.RolesData {
	var rolesList []*app.RolesData
	for _, r := range roles {
		rolesList = append(rolesList, convertRoleToAppRole(ctx, r))
	}
	return rolesList
}
func convertRoleToAppRole(ctx context.Context, r role.Role) *app.RolesData {
	return &app.RolesData{}
}

func convertIdentityRoleToAppRoles(ctx context.Context, roles []role.IdentityRole) []*app.RolesData {
	var rolesList []*app.RolesData
	for _, r := range roles {
		rolesList = append(rolesList, convertIdentityRoleToAppRole(ctx, r))
	}
	return rolesList
}
func convertIdentityRoleToAppRole(ctx context.Context, r role.IdentityRole) *app.RolesData {
	return &app.RolesData{}
}
