package controller

import (
	"context"

	accountservice "github.com/fabric8-services/fabric8-auth/account/service"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/token"

	"github.com/goadesign/goa"
)

// UserController implements the user resource.
type UserController struct {
	*goa.Controller
	app           application.Application
	config        UserControllerConfiguration
	tokenManager  token.Manager
	tenantService accountservice.TenantService
}

// UserControllerConfiguration the Configuration for the UserController
type UserControllerConfiguration interface {
	GetCacheControlUser() string
}

// NewUserController creates a user controller.
func NewUserController(service *goa.Service, app application.Application, config UserControllerConfiguration, tokenManager token.Manager, tenantService accountservice.TenantService) *UserController {
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

// ListSpaces returns a list of spaces in which the current user has a role
func (c *UserController) ListSpaces(ctx *app.ListSpacesUserContext) error {
	identityID, err := c.tokenManager.Locate(ctx)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Bad Token")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("bad or missing token"))
	}
	roles, err := c.app.RoleManagementService().ListAvailableRolesByResourceTypeAndIdentity(ctx, authorization.ResourceTypeSpace, identityID)
	log.Info(ctx, map[string]interface{}{"roles": len(roles), "identity_id": identityID.String()}, "retrieve resources with a role for the current user")
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	return ctx.OK(convertToUserSpaces(roles))
}
