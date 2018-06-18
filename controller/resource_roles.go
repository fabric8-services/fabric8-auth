package controller

import (
	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
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

	var roles []role.IdentityRole
	var err error
	var currentIdentity *account.Identity

	currentIdentity, err = login.LoadContextIdentityIfNotDeprovisioned(ctx, c.app)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
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
	currentIdentity, err := login.LoadContextIdentityIfNotDeprovisioned(ctx, c.app)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	var roles []role.IdentityRole

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

	currentUser, err := login.ContextIdentity(ctx)
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
	err = c.app.RoleManagementService().Assign(ctx, *currentUser, roleAssignments, ctx.ResourceID, false)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	return ctx.NoContent()
}

func convertIdentityRoleToAppRoles(roles []role.IdentityRole) []*app.IdentityRolesData {
	var rolesList []*app.IdentityRolesData
	for _, r := range roles {
		rolesList = append(rolesList, convertIdentityRoleToAppRole(r))
	}
	return rolesList
}

func convertIdentityRoleToAppRole(r role.IdentityRole) *app.IdentityRolesData {
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
