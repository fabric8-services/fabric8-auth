package controller

import (
	"context"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/authorization"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	rolerepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	autherrors "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/token"

	errs "github.com/pkg/errors"

	"fmt"

	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
)

// CollaboratorsController implements the collaborators resource.
type CollaboratorsController struct {
	*goa.Controller
	app    application.Application
	config collaboratorsConfiguration
}

type collaboratorsConfiguration interface {
	GetCacheControlCollaborators() string
}

// NewCollaboratorsController creates a collaborators controller.
func NewCollaboratorsController(service *goa.Service, app application.Application, config collaboratorsConfiguration) *CollaboratorsController {
	return &CollaboratorsController{Controller: service.NewController("CollaboratorsController"), app: app, config: config}
}

// List collaborators for the given space ID.
func (c *CollaboratorsController) List(ctx *app.ListCollaboratorsContext) error {
	err := c.checkSpaceExist(ctx, ctx.SpaceID.String())
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	isServiceAccount := token.IsSpecificServiceAccount(ctx, token.Notification)

	var currentIdentity *account.Identity
	if !isServiceAccount {
		currentIdentity, err = login.LoadContextIdentityIfNotDeprovisioned(ctx, c.app)
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, err)
		}
	}

	cm := make(map[uuid.UUID]account.Identity) // Use map to check duplications
	var collaborators []account.Identity
	// Collect all contributors and admins of the space
	contributors, err := c.listRoles(ctx, currentIdentity, authorization.SpaceContributorRole, isServiceAccount)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	for _, c := range contributors {
		cm[c.IdentityID] = c.Identity
		collaborators = append(collaborators, c.Identity)
	}
	admins, err := c.listRoles(ctx, currentIdentity, authorization.SpaceAdminRole, isServiceAccount)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	for _, a := range admins {
		if _, found := cm[a.IdentityID]; !found { // Add admins only if they are not already added as contributors
			collaborators = append(collaborators, a.Identity)
		}
	}

	count := len(collaborators)
	offset, limit := computePagingLimits(ctx.PageOffset, ctx.PageLimit)
	pageOffset := offset
	pageLimit := offset + limit
	if offset > count {
		pageOffset = count
	}
	if offset+limit > count {
		pageLimit = count
	}
	page := collaborators[pageOffset:pageLimit]
	resultIdentities := make([]account.Identity, len(page))
	resultUsers := make([]account.User, len(page))
	for i, idn := range page {
		user, err := c.app.Users().Load(ctx, idn.UserID.UUID)
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, autherrors.NewInternalError(ctx, err))
		}
		idn.User = *user
		resultUsers[i] = idn.User
		resultIdentities[i] = idn
	}
	log.Debug(ctx, map[string]interface{}{"offset": offset, "limit": limit, "page_offset": pageOffset, "page_limit": pageLimit, "count": len(resultIdentities), "resource_id": ctx.SpaceID.String()}, "listed collaborators for resource")

	return ctx.ConditionalEntities(resultUsers, c.config.GetCacheControlCollaborators, func() error {
		data := make([]*app.UserData, len(page))
		for i := range resultUsers {
			appUser := ConvertToAppUser(ctx.RequestData, &resultUsers[i], &resultIdentities[i], isServiceAccount)
			data[i] = appUser.Data
		}
		response := app.UserList{
			Links: &app.PagingLinks{},
			Meta:  &app.UserListMeta{TotalCount: count},
			Data:  data,
		}
		setPagingLinks(response.Links, buildAbsoluteURL(ctx.RequestData), len(page), offset, limit, count)
		return ctx.OK(&response)
	})
}

func (c *CollaboratorsController) listRoles(ctx *app.ListCollaboratorsContext, currentIdentity *account.Identity, roleName string, isServiceAccount bool) ([]rolerepo.IdentityRole, error) {
	//if isServiceAccount {
	// We can't check if the current identity has permissions to list collaborators because it breaks the existing collaborators API
	// So, using the repo which doesn't check permissions instead of the service even if the current identity is not a service account
	return c.app.IdentityRoleRepository().FindIdentityRolesByResourceAndRoleName(ctx, ctx.SpaceID.String(), roleName, false)
	//}
	//return c.app.RoleManagementService().ListByResourceAndRoleName(ctx, currentIdentity.ID, ctx.SpaceID.String(), roleName)
}

func (c *CollaboratorsController) checkSpaceExist(ctx context.Context, spaceID string) error {
	err := c.app.ResourceRepository().CheckExists(ctx, spaceID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":      err,
			"space_id": spaceID,
		}, "space not found")
		return err
	}
	return nil
}

// Add user's identity to the list of space collaborators.
func (c *CollaboratorsController) Add(ctx *app.AddCollaboratorsContext) error {
	currentIdentity, err := login.LoadContextIdentityIfNotDeprovisioned(ctx, c.app)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	identityIDs := []*app.UpdateUserID{{ID: ctx.IdentityID}}
	// Assign contributor role to the collaborator
	err = c.addContributors(ctx, currentIdentity.ID, identityIDs, ctx.SpaceID.String())
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":      err,
			"space_id": ctx.SpaceID,
		}, "unable to add contributors to space resource: resource not found; that's OK for old spaces")
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	return ctx.OK([]byte{})
}

// AddMany adds user's identities to the list of space collaborators.
func (c *CollaboratorsController) AddMany(ctx *app.AddManyCollaboratorsContext) error {
	currentIdentity, err := login.LoadContextIdentityIfNotDeprovisioned(ctx, c.app)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	if ctx.Payload != nil && ctx.Payload.Data != nil {
		// Assign contributor role to the collaborators
		err := c.addContributors(ctx, currentIdentity.ID, ctx.Payload.Data, ctx.SpaceID.String())
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"err":      err,
				"space_id": ctx.SpaceID,
			}, "unable to add contributors to space resource: resource not found; that's OK for old spaces")
			return jsonapi.JSONErrorResponse(ctx, err)
		}
	}

	return ctx.OK([]byte{})
}

func (c *CollaboratorsController) addContributors(ctx context.Context, currentIdentity uuid.UUID, contributors []*app.UpdateUserID, spaceID string) error {
	err := c.checkSpaceExist(ctx, spaceID)
	if err != nil {
		return err
	}

	err = c.app.PermissionService().RequireScope(ctx, currentIdentity, spaceID, authorization.ManageRoleAssignmentsInSpaceScope)
	if err != nil {
		return err
	}

	res := resource.Resource{ResourceType: resourcetype.ResourceType{Name: authorization.ResourceTypeSpace}, ResourceID: spaceID}
	for _, contributor := range contributors {
		identityID, err := uuid.FromString(contributor.ID)
		if err != nil {
			return autherrors.NewBadParameterError("ids", contributor.ID).Expected("uuid")
		}

		// Have to use ForceAssign() because Assign() requires assignees to already have any role in the space
		err = c.app.RoleManagementService().ForceAssign(ctx, identityID, authorization.SpaceContributorRole, res)
		if err != nil {

			if _, ok := errs.Cause(err).(autherrors.DataConflictError); ok {
				// If the error occured because the user is already a contributor
				// we log the error, and proceed - instead of returning a non-200 response.
				log.Warn(ctx, map[string]interface{}{
					"err":      err,
					"identity": contributor.ID,
					"resource": res.ResourceID,
				}, "identity already has the contributor role(s) associated with the resource")
			} else {
				return err
			}
		}
	}

	return nil
}

// Remove user from the list of space collaborators.
func (c *CollaboratorsController) Remove(ctx *app.RemoveCollaboratorsContext) error {
	currentIdentity, err := login.LoadContextIdentityIfNotDeprovisioned(ctx, c.app)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	identityIDs := []*app.UpdateUserID{{ID: ctx.IdentityID}}
	// Delete the contributor role from the collaborator
	err = c.removeContributors(ctx, currentIdentity.ID, identityIDs, ctx.SpaceID.String())
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	return ctx.OK([]byte{})
}

// RemoveMany removes users from the list of space collaborators.
func (c *CollaboratorsController) RemoveMany(ctx *app.RemoveManyCollaboratorsContext) error {
	currentIdentity, err := login.LoadContextIdentityIfNotDeprovisioned(ctx, c.app)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	if ctx.Payload != nil && ctx.Payload.Data != nil {
		// Delete the contributor role from the collaborators
		err := c.removeContributors(ctx, currentIdentity.ID, ctx.Payload.Data, ctx.SpaceID.String())
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, err)
		}
	}

	return ctx.OK([]byte{})
}

func (c *CollaboratorsController) removeContributors(ctx context.Context, byIdentityID uuid.UUID, contributors []*app.UpdateUserID, spaceID string) error {
	err := c.checkSpaceExist(ctx, spaceID)
	if err != nil {
		return err
	}

	// Get the list of all admins to make sure we don't remove the last one
	admins, err := c.app.IdentityRoleRepository().FindIdentityRolesByResourceAndRoleName(ctx, spaceID, authorization.SpaceAdminRole, false)
	if err != nil {
		return err
	}

	toDelete := []uuid.UUID{}
	for _, contributor := range contributors {
		identityID, err := uuid.FromString(contributor.ID)
		if err != nil {
			return autherrors.NewBadParameterError("ids", contributor.ID).Expected("uuid")
		}
		toDelete = append(toDelete, identityID)
		for i, admin := range admins {
			if identityID == admin.IdentityID {
				admins = append(admins[:i], admins[i+1:]...)
			}
		}
	}
	if len(admins) == 0 {
		return autherrors.NewBadParameterErrorFromString("ids", fmt.Sprintf("%v", contributors), "space should have at least one admin")
	}
	return c.app.RoleManagementService().RevokeResourceRoles(ctx, byIdentityID, toDelete, spaceID)
}
