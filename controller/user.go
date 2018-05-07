package controller

import (
	"context"

	"github.com/fabric8-services/fabric8-auth/account/service"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/token"

	"github.com/goadesign/goa"
)

// UserController implements the user resource.
type UserController struct {
	*goa.Controller
	userInfoService service.UserInfoService
	app             application.Application
	tokenManager    token.Manager
	config          UserControllerConfiguration
	tenantService   service.Tenant
}

// UserControllerConfiguration the Configuration for the UserController
type UserControllerConfiguration interface {
	GetCacheControlUser() string
}

// NewUserController creates a user controller.
func NewUserController(service *goa.Service, userInfoService service.UserInfoService, app application.Application, tokenManager token.Manager, config UserControllerConfiguration, tenantService service.Tenant) *UserController {
	return &UserController{
		Controller:      service.NewController("UserController"),
		userInfoService: userInfoService,
		app:             app,
		tokenManager:    tokenManager,
		config:          config,
		tenantService:   tenantService,
	}
}

// Show returns the authorized user based on the provided Token
func (c *UserController) Show(ctx *app.ShowUserContext) error {
	user, identity, err := c.userInfoService.UserInfo(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	if user.Deprovisioned {
		ctx.ResponseData.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate")
		ctx.ResponseData.Header().Set("WWW-Authenticate", "DEPROVISIONED description=\"Account has been deprovisioned\"")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("Account has been deprovisioned"))
	}

	return ctx.ConditionalRequest(*user, c.config.GetCacheControlUser, func() error {
		if c.tenantService != nil {
			go func(ctx context.Context) {
				c.tenantService.Init(ctx)
			}(ctx)
		}
		return ctx.OK(ConvertToAppUser(ctx.RequestData, user, identity, true))
	})
}
