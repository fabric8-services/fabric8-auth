package controller

import (
	"errors"
	"strings"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/auth"
	autherrors "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/space/authz"
	"github.com/fabric8-services/fabric8-auth/token"

	"github.com/fabric8-services/fabric8-auth/application/transaction"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
)

// CollaboratorsController implements the collaborators resource.
type CollaboratorsController struct {
	*goa.Controller
	app           application.Application
	config        collaboratorsConfiguration
	policyManager auth.AuthzPolicyManager
}

type collaboratorsConfiguration interface {
	GetKeycloakEndpointEntitlement(*goa.RequestData) (string, error)
	GetCacheControlCollaborators() string
}

// NewCollaboratorsController creates a collaborators controller.
func NewCollaboratorsController(service *goa.Service, app application.Application, config collaboratorsConfiguration, policyManager auth.AuthzPolicyManager) *CollaboratorsController {
	return &CollaboratorsController{Controller: service.NewController("CollaboratorsController"), app: app, config: config, policyManager: policyManager}
}

// List collaborators for the given space ID.
func (c *CollaboratorsController) List(ctx *app.ListCollaboratorsContext) error {
	isServiceAccount := token.IsSpecificServiceAccount(ctx, token.Notification)

	policy, _, err := c.getPolicy(ctx, ctx.RequestData, ctx.SpaceID)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	userIDs := policy.Config.UserIDs
	//UsersIDs format : "[\"<ID>\",\"<ID>\"]"
	s := strings.Split(userIDs, ",")
	count := len(s)

	offset, limit := computePagingLimits(ctx.PageOffset, ctx.PageLimit)

	pageOffset := offset
	pageLimit := offset + limit
	if offset > len(s) {
		pageOffset = len(s)
	}
	if offset+limit > len(s) {
		pageLimit = len(s)
	}
	page := s[pageOffset:pageLimit]
	resultIdentities := make([]account.Identity, len(page))
	resultUsers := make([]account.User, len(page))
	for i, id := range page {
		id = strings.Trim(id, "[]\"")
		uID, err := uuid.FromString(id)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"identity_id": id,
				"users-ids":   userIDs,
			}, "unable to convert the identity ID to uuid v4")
			return jsonapi.JSONErrorResponse(ctx, goa.ErrInternal(err.Error()))
		}
		err = transaction.Transactional(c.app, func(tr transaction.TransactionalResources) error {
			identities, err := tr.Identities().Query(account.IdentityFilterByID(uID), account.IdentityWithUser())
			if err != nil {
				log.Error(ctx, map[string]interface{}{
					"identity_id": id,
					"err":         err,
				}, "unable to find the identity listed in the space policy")
				return err
			}
			if len(identities) == 0 {
				log.Error(ctx, map[string]interface{}{
					"identity_id": id,
				}, "unable to find the identity listed in the space policy")
				return errors.New("Identity listed in the space policy not found")
			}
			resultIdentities[i] = identities[0]
			resultUsers[i] = identities[0].User
			return nil
		})
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, goa.ErrInternal(err.Error()))
		}
	}

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

// Add user's identity to the list of space collaborators.
func (c *CollaboratorsController) Add(ctx *app.AddCollaboratorsContext) error {
	_, err := login.LoadContextIdentityIfNotDeprovisioned(ctx, c.app)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	identityIDs := []*app.UpdateUserID{{ID: ctx.IdentityID}}
	err = c.updatePolicy(ctx, ctx.RequestData, ctx.SpaceID, identityIDs, c.policyManager.AddUserToPolicy)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	return ctx.OK([]byte{})
}

// AddMany adds user's identities to the list of space collaborators.
func (c *CollaboratorsController) AddMany(ctx *app.AddManyCollaboratorsContext) error {
	_, err := login.LoadContextIdentityIfNotDeprovisioned(ctx, c.app)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	if ctx.Payload != nil && ctx.Payload.Data != nil {
		err := c.updatePolicy(ctx, ctx.RequestData, ctx.SpaceID, ctx.Payload.Data, c.policyManager.AddUserToPolicy)
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, err)
		}
	}
	return ctx.OK([]byte{})
}

// Remove user from the list of space collaborators.
func (c *CollaboratorsController) Remove(ctx *app.RemoveCollaboratorsContext) error {
	_, err := login.LoadContextIdentityIfNotDeprovisioned(ctx, c.app)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	identityIDs := []*app.UpdateUserID{{ID: ctx.IdentityID}}
	err = c.updatePolicy(ctx, ctx.RequestData, ctx.SpaceID, identityIDs, c.policyManager.RemoveUserFromPolicy)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	return ctx.OK([]byte{})
}

// RemoveMany removes users from the list of space collaborators.
func (c *CollaboratorsController) RemoveMany(ctx *app.RemoveManyCollaboratorsContext) error {
	_, err := login.LoadContextIdentityIfNotDeprovisioned(ctx, c.app)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	if ctx.Payload != nil && ctx.Payload.Data != nil {
		err = c.updatePolicy(ctx, ctx.RequestData, ctx.SpaceID, ctx.Payload.Data, c.policyManager.RemoveUserFromPolicy)
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, err)
		}
	}

	return ctx.OK([]byte{})
}

func (c *CollaboratorsController) updatePolicy(ctx jsonapi.InternalServerError, req *goa.RequestData, spaceID uuid.UUID, identityIDs []*app.UpdateUserID, update func(policy *auth.KeycloakPolicy, identityID string) bool) error {
	// Authorize current user
	authorized, err := authz.Authorize(ctx, spaceID.String())
	if err != nil {
		return goa.ErrUnauthorized(err.Error())
	}
	if !authorized {
		return goa.ErrUnauthorized("User not among space collaborators")
	}

	// Update policy
	policy, pat, err := c.getPolicy(ctx, req, spaceID)
	if err != nil {
		return err
	}
	updated := false
	for _, identityIDData := range identityIDs {
		if identityIDData != nil {
			identityID := identityIDData.ID
			identityUUID, err := uuid.FromString(identityID)
			if err != nil {
				log.Error(ctx, map[string]interface{}{
					"identity_id": identityID,
				}, "unable to convert the identity ID to uuid v4")
				return goa.ErrBadRequest(err.Error())
			}
			var ownerID uuid.UUID
			err = transaction.Transactional(c.app, func(tr transaction.TransactionalResources) error {
				identities, err := tr.Identities().Query(account.IdentityFilterByID(identityUUID), account.IdentityWithUser())
				if err != nil {
					log.Error(ctx, map[string]interface{}{
						"identity_id": identityID,
						"err":         err,
					}, "unable to query for the identity")
					return err
				}
				if len(identities) == 0 {
					log.Error(ctx, map[string]interface{}{
						"identity_id": identityID,
					}, "unable to find the identity")
					return autherrors.NewNotFoundError("identity", identityID)
				}
				resource, err := tr.SpaceResources().LoadBySpace(ctx, &spaceID)
				if err != nil {
					return err
				}
				ownerID = resource.OwnerID
				return nil
			})
			if err != nil {
				return err
			}
			updated = update(policy, identityID) || updated
			if !strings.Contains(policy.Config.UserIDs, ownerID.String()) {
				// Updated policy has no User IDs
				return autherrors.NewBadParameterError("identity", identityID).Expected("not the space owner")
			}
		}
	}
	if !updated {
		// Nothing changed. No need to update
		return nil
	}

	err = c.policyManager.UpdatePolicy(ctx, req, *policy, *pat)
	if err != nil {
		return goa.ErrInternal(err.Error())
	}

	// We need to update the resource to triger RPT token refreshing when users try to access this space
	err = transaction.Transactional(c.app, func(tr transaction.TransactionalResources) error {
		resource, err := tr.SpaceResources().LoadBySpace(ctx, &spaceID)
		_, err = tr.SpaceResources().Save(ctx, resource)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"resource":   resource,
				"space_uuid": spaceID.String(),
				"err":        err,
			}, "unable to update the space resource")
			return err
		}
		return nil
	})
	if err != nil {
		return goa.ErrInternal(err.Error())
	}

	return nil
}

func (c *CollaboratorsController) getPolicy(ctx jsonapi.InternalServerError, req *goa.RequestData, spaceID uuid.UUID) (*auth.KeycloakPolicy, *string, error) {
	var policyID string
	err := transaction.Transactional(c.app, func(tr transaction.TransactionalResources) error {
		// Load associated space resource
		resource, err := tr.SpaceResources().LoadBySpace(ctx, &spaceID)
		if err != nil {
			return err
		}
		policyID = resource.PolicyID
		return nil
	})

	if err != nil {
		return nil, nil, goa.ErrNotFound(err.Error())
	}
	policy, pat, err := c.policyManager.GetPolicy(ctx, req, policyID)
	if err != nil {
		return nil, nil, goa.ErrInternal(err.Error())
	}
	return policy, pat, nil
}
