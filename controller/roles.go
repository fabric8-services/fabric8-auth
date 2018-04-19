package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/goadesign/goa"
)

// RolesController implements the roles resource.
type RolesController struct {
	*goa.Controller
	db application.DB
}

// NewRolesController creates a roles controller.
func NewRolesController(service *goa.Service, db application.DB) *RolesController {
	return &RolesController{
		Controller: service.NewController("RolesController"),
		db:         db,
	}
}

// List runs the list action.
func (c *RolesController) List(ctx *app.ListRolesContext) error {
	if ctx.ResourceType == nil { // todo: check for empty string too?
		return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("resource_type", "nil"))
	}

	var roleScopes []role.RoleScope
	err := application.Transactional(c.db, func(appl application.Application) error {
		_, err := appl.ResourceTypeRepository().Lookup(ctx, *ctx.ResourceType)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"resource_type": *ctx.ResourceType,
				"err":           err,
			}, "error getting roles for the resource type")
			// if not found, then NotFoundError would be returned,
			// hence returning the error as is.
			return err
		}

		roleScopes, err = appl.RoleManagementModelService().ListAvailableRolesByResourceType(ctx, *ctx.ResourceType)
		return err
	})

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_type": *ctx.ResourceType,
			"err":           err,
		}, "error getting avaiable roles for the resource")
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	respRoles := convertRoleScopeToAppRoles(roleScopes)
	res := &app.Roles{
		Data: respRoles,
	}
	return ctx.OK(res)
}

func convertRoleScopeToAppRoles(roles []role.RoleScope) []*app.RolesData {
	var rolesList []*app.RolesData
	for _, r := range roles {
		rolesList = append(rolesList, convertRoleScopeToAppRole(r))
	}
	return rolesList
}

func convertRoleScopeToAppRole(r role.RoleScope) *app.RolesData {
	return &app.RolesData{
		RoleName:     r.RoleName,
		ResourceType: r.ResourceType,
		Scope:        r.Scopes,
	}
}
