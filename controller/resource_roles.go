package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/authorization"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/token"
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

	err := c.app.ResourceRepository().CheckExists(ctx, ctx.ResourceID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": ctx.ResourceID,
			"err":         err,
		}, "does not exist")
		return jsonapi.JSONErrorResponse(ctx, errors.NewNotFoundError("resource_id", ctx.ResourceID))
	}

	roles, err = c.app.RoleManagementService().ListByResource(ctx, ctx.ResourceID)

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

	var roles []role.IdentityRole

	err := c.app.ResourceRepository().CheckExists(ctx, ctx.ResourceID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": ctx.ResourceID,
			"err":         err,
		}, "does not exist")
		return jsonapi.JSONErrorResponse(ctx, errors.NewNotFoundError("resource_id", ctx.ResourceID))
	}

	roles, err = c.app.RoleManagementService().ListByResourceAndRoleName(ctx, ctx.ResourceID, ctx.RoleName)

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

	isMigration := token.IsSpecificServiceAccount(ctx, "space-migration")

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

	// Temporary: During migration, if the service account token is used to call this API,
	// then the 'contributor' role can be added to existing space collaborators.
	// Without this, the Assign() service method will not allow a role to be assigned since the user does not have a prior
	// associattion with this space
	if isMigration {
		res := resource.Resource{
			ResourceType: resourcetype.ResourceType{Name: authorization.ResourceTypeSpace},
			ResourceID:   ctx.ResourceID,
		}
		for rolename, assignedTo := range roleAssignments {
			for _, assignee := range assignedTo {
				err = c.app.RoleManagementService().ForceAssign(ctx, assignee, rolename, res)
				if err != nil {
					return jsonapi.JSONErrorResponse(ctx, err)
				}
			}
		}
	} else {
		err = c.app.RoleManagementService().Assign(ctx, *currentUser, roleAssignments, ctx.ResourceID, false)
	}
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
