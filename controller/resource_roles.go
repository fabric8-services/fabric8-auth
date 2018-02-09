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
func NewResourceRolesController(service *goa.Service, tokenManager token.Manager, db application.DB) *ResourceRolesController {
	return &ResourceRolesController{Controller: service.NewController("ResourceRolesController"), db: db, TokenManager: tokenManager}
}

// ListAssigned runs the list action.
func (c *ResourceRolesController) ListAssigned(ctx *app.ListAssignedResourceRolesContext) error {
	var roles []role.IdentityRole
	err := application.Transactional(c.db, func(appl application.Application) error {
		err := appl.ResourceRepository().CheckExists(ctx, ctx.ID)
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, err)
		}
		roles, err = appl.IdentityRoleRepository().ListByResource(ctx, ctx.ID)
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
	roleList := convertIdentityRoleToAppRoles(ctx, roles)
	return ctx.OK(&app.Identityroles{
		Data: roleList,
	})
}

// List runs the list action.
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
	return &app.RolesData{
		RoleID:   r.RoleID.String(),
		RoleName: r.Name,
	}
}

func convertIdentityRoleToAppRoles(ctx context.Context, roles []role.IdentityRole) []*app.IdentityRolesData {
	var rolesList []*app.IdentityRolesData
	for _, r := range roles {
		rolesList = append(rolesList, convertIdentityRoleToAppRole(ctx, r))
	}
	return rolesList
}
func convertIdentityRoleToAppRole(ctx context.Context, r role.IdentityRole) *app.IdentityRolesData {
	inherited := false
	if r.Resource.ParentResourceID != nil {
		inherited = true
	}
	rolesData := app.IdentityRolesData{
		Identifier:   r.IdentityRoleID.String(),
		AssigneeID:   r.Identity.ID.String(),
		AssigneeType: "user", // will change for teams/orgs/groups
		Inherited:    inherited,
		RoleID:       r.Role.RoleID.String(),
		RoleName:     r.Role.Name,
	}
	if inherited {
		rolesData.InheritedFrom = r.Resource.ParentResourceID
	}
	return &rolesData
}
