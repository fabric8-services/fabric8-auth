package controller

import (
	"fmt"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/authorization"
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

	currentUser, err := login.ContextIdentity(ctx)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": ctx.ResourceID,
			"role":        ctx.RoleName,
		}, "error getting identity information from token")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError(err.Error()))
	}

	// check if the current user token belongs to a user who has the necessary privileges
	// for assigning roles to other users.

	hasScope, err := c.app.PermissionService().HasScope(ctx, *currentUser, ctx.ResourceID, authorization.ManageTeamsInSpaceScope)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": ctx.ResourceID,
			"identity_id": *currentUser,
			"role":        ctx.RoleName,
		}, "error determining if user has manage scope")
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	if !hasScope {
		log.Error(ctx, map[string]interface{}{
			"resource_id": ctx.ResourceID,
			"identity_id": *currentUser,
			"role":        ctx.RoleName,
		}, "user not authorizied to assign roles")
		return jsonapi.JSONErrorResponse(ctx, errors.NewForbiddenError("user is not authorized to assign roles"))
	}

	var identitiesToBeAssigned []uuid.UUID
	for _, identity := range ctx.Payload.Data {
		identityIDAsUUID, err := uuid.FromString(identity.ID)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"resource_id": ctx.ResourceID,
				"identity_id": identity.ID,
				"role":        ctx.RoleName,
			}, "invalid identity ID")
			return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("identity", identity.ID).Expected("uuid"))
		}
		identitiesToBeAssigned = append(identitiesToBeAssigned, identityIDAsUUID)
	}

	// In batch assignment of roles all selected users must have previously been assigned
	// privileges for the resource, otherwise the invitation workflow should be used instead
	for _, identityIDAsUUID := range identitiesToBeAssigned {
		assignedRoles, err := c.app.IdentityRoleRepository().FindIdentityRolesByIdentityAndResource(ctx, ctx.ResourceID, identityIDAsUUID)
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, err)
		}
		if len(assignedRoles) == 0 {
			log.Error(ctx, map[string]interface{}{
				"resource_id": ctx.ResourceID,
				"identity_id": identityIDAsUUID,
				"role":        ctx.RoleName,
			}, "identity not part of a  resource cannot be assigned a role")
			return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterErrorFromString("identityID", identityIDAsUUID, fmt.Sprintf("cannot update roles for an identity %s without an existing role", identityIDAsUUID)))
		}
	}

	// Now that we have confirmed that all users have pre-existing role assignments
	// we can proceed with the assignment of roles.
	for _, identityIDAsUUID := range identitiesToBeAssigned {
		err = c.app.RoleManagementService().Assign(ctx, identityIDAsUUID, ctx.ResourceID, ctx.RoleName)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"resource_id": ctx.ResourceID,
				"identity_id": identityIDAsUUID,
				"role":        ctx.RoleName,
			}, "assignment failed")
			return jsonapi.JSONErrorResponse(ctx, err)
		}
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
