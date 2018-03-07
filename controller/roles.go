package controller

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	role "github.com/fabric8-services/fabric8-auth/authorization/role"
	roleservice "github.com/fabric8-services/fabric8-auth/authorization/role/service"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/goadesign/goa"
)

// RolesController implements the roles resource.
type RolesController struct {
	*goa.Controller
	db                    application.DB
	roleManagementService roleservice.RoleManagementService
}

// NewRolesController creates a roles controller.
func NewRolesController(service *goa.Service, db application.DB, roleManagementService roleservice.RoleManagementService) *RolesController {
	return &RolesController{
		Controller: service.NewController("RolesController"),
		db:         db,
		roleManagementService: roleManagementService,
	}
}

// List runs the list action.
func (c *RolesController) List(ctx *app.ListRolesContext) error {
	var roles []role.RoleScope
	if ctx.ResourceType == nil { // todo: check for empty string too?
		return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("resource_type", "nil"))
	}
	roles, err := c.roleManagementService.ListAvailableRolesByResourceType(ctx, *ctx.ResourceType)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_type": ctx.ResourceType,
			"err":           err,
		}, "error getting avaiable roles for the resource")
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	respRoles := convertRoleScopeToAppRoles(ctx, roles)
	res := &app.Roles{
		Data: respRoles,
	}
	return ctx.OK(res)
}

func convertRoleScopeToAppRoles(ctx context.Context, roles []role.RoleScope) []*app.RolesData {
	var rolesList []*app.RolesData
	for _, r := range roles {
		rolesList = append(rolesList, convertRoleScopeToAppRole(ctx, r))
	}
	return rolesList
}
func convertRoleScopeToAppRole(ctx context.Context, r role.RoleScope) *app.RolesData {
	return &app.RolesData{
		RoleName:     r.RoleName,
		ResourceType: r.ResourceType,
		Scope:        r.Scopes,
	}
}
