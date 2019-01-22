package controller

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/authorization/token"
	"github.com/satori/go.uuid"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	accountservice "github.com/fabric8-services/fabric8-auth/authentication/account/service"
	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"

	"github.com/goadesign/goa"
)

// UserController implements the user resource.
type UserController struct {
	*goa.Controller
	app           application.Application
	config        UserControllerConfiguration
	tokenManager  manager.TokenManager
	tenantService accountservice.TenantService
}

// UserControllerConfiguration the Configuration for the UserController
type UserControllerConfiguration interface {
	GetCacheControlUser() string
}

// NewUserController creates a user controller.
func NewUserController(service *goa.Service, app application.Application, config UserControllerConfiguration,
	tokenManager manager.TokenManager, tenantService accountservice.TenantService) *UserController {
	return &UserController{
		Controller:    service.NewController("UserController"),
		app:           app,
		config:        config,
		tokenManager:  tokenManager,
		tenantService: tenantService,
	}
}

// Show returns the authorized user based on the provided Token
func (c *UserController) Show(ctx *app.ShowUserContext) error {
	// retrieve the user's identity ID from the token
	identityID, err := c.tokenManager.Locate(ctx)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Bad Token")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("bad or missing token"))
	}
	user, identity, err := c.app.UserService().UserInfo(ctx, identityID)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	if user.Deprovisioned {
		ctx.ResponseData.Header().Add("Access-Control-Expose-Headers", "WWW-Authenticate")
		ctx.ResponseData.Header().Set("WWW-Authenticate", "DEPROVISIONED description=\"Account has been deprovisioned\"")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("Account has been deprovisioned"))
	}

	return ctx.ConditionalRequest(*user, c.config.GetCacheControlUser, func() error {
		// Init tenant (if access to tenant service is configured/enabled)
		if c.tenantService != nil {
			go func(ctx context.Context) {
				c.tenantService.Init(ctx)
			}(ctx)
		}
		return ctx.OK(ConvertToAppUser(ctx.RequestData, user, identity, true))
	})
}

// ListResources returns a list of resources in which the current user has a role
func (c *UserController) ListResources(ctx *app.ListResourcesUserContext) error {
	// retrieve the user's identity ID from the token
	identityID, err := c.tokenManager.Locate(ctx)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Bad Token")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("bad or missing token"))
	}
	resourceType := ctx.Type
	if resourceType != authorization.ResourceTypeSpace {
		return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterErrorFromString("type", ctx.Type, "invalid or unsupported type of resource."))
	}

	resourceIDs, err := c.app.ResourceService().FindWithRoleByResourceTypeAndIdentity(ctx, resourceType, identityID)
	log.Info(ctx, map[string]interface{}{"matching_resources": len(resourceIDs), "identity_id": identityID.String()}, "retrieved resources with a role for the current user")
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	return ctx.OK(convertToUserResources(ctx.RequestData, resourceType, resourceIDs))
}

// ListTokens lists all of the tokens for the specified identity.  This endpoint may only be invoked via the admin console
// service account
func (c *UserController) ListTokens(ctx *app.ListTokensUserContext) error {
	isSvcAccount := token.IsSpecificServiceAccount(ctx, token.Admin)
	if !isSvcAccount {
		log.Error(ctx, nil, "The account is not an authorized service account allowed to manage user tokens")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("account not authorized to manage user tokens."))
	}

	identityID, err := uuid.FromString(ctx.IdentityID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Invalid identityID")
		return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterErrorFromString("identity_id", ctx.IdentityID, "invalid identity_id - not a UUID"))
	}

	tokens, err := c.app.TokenRepository().ListForIdentity(ctx, identityID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "error retrieving user tokens")
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	response := &app.UserTokenArray{}

	for _, t := range tokens {
		perms := []*app.TokenPrivilegeData{}

		// If the token is an RPT token, include its privileges in the response
		if t.TokenType == token.TOKEN_TYPE_RPT {
			privs, err := c.app.TokenRepository().ListPrivileges(ctx, t.TokenID)
			if err != nil {
				log.Error(ctx, map[string]interface{}{
					"err": err,
				}, "error retrieving token privileges")
				return jsonapi.JSONErrorResponse(ctx, err)
			}

			for _, priv := range privs {
				perms = append(perms, &app.TokenPrivilegeData{
					ResourceID: priv.ResourceID,
					Scopes:     priv.Scopes,
					Stale:      priv.Stale,
				})
			}
		}

		response.Data = append(response.Data, &app.UserTokenData{
			TokenID:     t.TokenID.String(),
			TokenType:   t.TokenType,
			Status:      t.Status,
			ExpiryTime:  t.ExpiryTime,
			Permissions: perms,
		})
	}

	return ctx.OK(response)
}

// convertToUserResources converts a list of resources to which the user has a role
func convertToUserResources(request *goa.RequestData, resourceType string, resourceIDs []string) *app.UserResourcesList {
	data := make([]*app.UserResourceData, 0)
	for _, resourceID := range resourceIDs {
		resourceHref := rest.AbsoluteURL(request, app.ResourceHref(resourceID), nil)
		data = append(data, &app.UserResourceData{
			ID:   resourceID,
			Type: "resources",
			Links: &app.GenericLinks{
				Related: &resourceHref,
			},
		})
	}
	return &app.UserResourcesList{
		Data: data,
	}
}
