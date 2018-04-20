package controller

import (
	"fmt"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/goadesign/goa"
	uuid "github.com/satori/go.uuid"
)

const (
	// ROLE_ASSIGNMENT_SCOPE is the scope the user needs to have as part of the roles assigned to her
	// that will enabled her to assign roles to other users.
	ROLE_ASSIGNMENT_SCOPE = "assign_role" // The exact name will be refactored in a different PR/commit once we decide on the name of the role.

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
		err := appl.ResourceRepository().CheckExists(ctx, ctx.ResourceID)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"resource_id": ctx.ResourceID,
				"err":         err,
			}, "does not exist")
			return errors.NewNotFoundError("resource_id", ctx.ResourceID)
		}

		roles, err = appl.RoleManagementModelService().ListByResource(ctx, ctx.ResourceID)
		return err
	})

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

	err := application.Transactional(c.db, func(appl application.Application) error {
		err := appl.ResourceRepository().CheckExists(ctx, ctx.ResourceID)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"resource_id": ctx.ResourceID,
				"err":         err,
			}, "does not exist")
			return errors.NewNotFoundError("resource_id", ctx.ResourceID)
		}

		roles, err = appl.RoleManagementModelService().ListByResourceAndRoleName(ctx, ctx.ResourceID, ctx.RoleName)
		return err
	})

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
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError(err.Error()))
	}
	if currentUser == nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("identity ID not found in token"))
	}

	// check if the current user token belongs to a user who has the necessary privileges
	// for assigning roles to other users.

	hasScope, err := c.db.PermissionModelService().HasScope(ctx, *currentUser, ctx.ResourceID, ROLE_ASSIGNMENT_SCOPE)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	if !hasScope {
		return jsonapi.JSONErrorResponse(ctx, errors.NewForbiddenError("user is not authorized to assign roles"))
	}

	// In a batch assignment of roles, all users need to be a part of the resource
	// Only then futher role assignments would be allowed.
	for _, identity := range ctx.Payload.Data {
		identityIDAsUUID, err := uuid.FromString(identity.ID)
		assignedRoles, err := c.db.RoleManagementModelService().ListAssignmentsByIdentityAndResource(ctx, ctx.ResourceID, identityIDAsUUID)
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, err)
		}
		if len(assignedRoles) == 0 {
			log.Error(ctx, map[string]interface{}{
				"resource_id": ctx.ResourceID,
				"identity_id": identityIDAsUUID,
				"role":        ctx.RoleName,
			}, "identity not part of a  resource cannot be assigned a role")
			return jsonapi.JSONErrorResponse(ctx, errors.NewForbiddenError(fmt.Sprintf("identity %s does not belong to the resource", identity.ID)))
		}
	}

	// Now that we have confirmed that all users have pre-existing role assignments
	// we can proceed with the assignment of roles.
	var identityIDs []uuid.UUID
	for _, identity := range ctx.Payload.Data {
		identityIDAsUUID, err := uuid.FromString(identity.ID)
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("identityID", identity.ID).Expected("uuid"))
		}
		identityIDs = append(identityIDs, identityIDAsUUID)
		identityAsUUID, err := uuid.FromString(identity.ID)
		err = c.db.RoleManagementModelService().Assign(ctx, identityAsUUID, ctx.ResourceID, ctx.RoleName)
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
