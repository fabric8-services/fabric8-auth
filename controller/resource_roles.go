package controller

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	identityrole "github.com/fabric8-services/fabric8-auth/authorization/role/identityrole/repository"
	roleservice "github.com/fabric8-services/fabric8-auth/authorization/role/service"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/goadesign/goa"
	uuid "github.com/satori/go.uuid"
)

// ResourceRolesController implements the resource_roles resource.
type ResourceRolesController struct {
	*goa.Controller
	db                    application.DB
	roleManagementService roleservice.RoleManagementService
}

// NewResourceRolesController creates a resource_roles controller.
func NewResourceRolesController(service *goa.Service, db application.DB, assignmentService roleservice.RoleManagementService) *ResourceRolesController {
	return &ResourceRolesController{
		Controller: service.NewController("ResourceRolesController"),
		db:         db,
		roleManagementService: assignmentService,
	}
}

// ListAssigned runs the list action.
func (c *ResourceRolesController) ListAssigned(ctx *app.ListAssignedResourceRolesContext) error {

	var roles []identityrole.IdentityRole

	roles, err := c.roleManagementService.ListByResource(ctx, ctx.ResourceID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": ctx.ResourceID,
			"err":         err,
		}, "error retrieving list of roles for a specific resource")
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	roleList := convertIdentityRoleToAppRoles(ctx, roles)
	return ctx.OK(&app.Identityroles{
		Data: roleList,
	})
}

// ListAssignedByRoleName runs the list action.
func (c *ResourceRolesController) ListAssignedByRoleName(ctx *app.ListAssignedByRoleNameResourceRolesContext) error {

	var roles []identityrole.IdentityRole

	roles, err := c.roleManagementService.ListByResourceAndRoleName(ctx, ctx.ResourceID, ctx.RoleName)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": ctx.ResourceID,
			"err":         err,
		}, "error retrieving list of roles for a specific resource and a specific role")
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

// AssignRole assigns a specific role for a resource, to one or more identities.
func (c *ResourceRolesController) AssignRole(ctx *app.AssignRoleResourceRolesContext) error {
	var identityIDs []uuid.UUID
	var err error
	for _, identity := range ctx.Payload.Data {
		identityIDAsUUID, err := uuid.FromString(identity.ID)
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("identityID", identity.ID).Expected("uuid"))
		}
		identityIDs = append(identityIDs, identityIDAsUUID)
	}
	err = c.roleManagementService.Assign(ctx, identityIDs, ctx.ResourceID, ctx.RoleName)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	return ctx.NoContent()
}

func convertIdentityRoleToAppRoles(ctx context.Context, roles []identityrole.IdentityRole) []*app.IdentityRolesData {
	var rolesList []*app.IdentityRolesData
	for _, r := range roles {
		rolesList = append(rolesList, convertIdentityRoleToAppRole(ctx, r))
	}
	return rolesList
}
func convertIdentityRoleToAppRole(ctx context.Context, r identityrole.IdentityRole) *app.IdentityRolesData {
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
