package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	appservice "github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/authorization/token"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/goadesign/goa"
)

// NamedusersController implements the namedusers resource.
type NamedusersController struct {
	*goa.Controller
	app           application.Application
	config        UsersControllerConfiguration
	tenantService appservice.TenantService
}

// NewNamedusersController creates a namedusers controller.
func NewNamedusersController(service *goa.Service, app application.Application, config UsersControllerConfiguration, tenantService appservice.TenantService) *NamedusersController {
	return &NamedusersController{
		Controller:    service.NewController("NamedusersController"),
		app:           app,
		config:        config,
		tenantService: tenantService,
	}
}

// Ban runs the "ban" action.
func (c *NamedusersController) Ban(ctx *app.BanNamedusersContext) error {
	isSvcAccount := token.IsSpecificServiceAccount(ctx, token.OnlineRegistration)
	if !isSvcAccount {
		log.Error(ctx, nil, "the account is not an authorized service account allowed to deprovision users")
		return jsonapi.JSONErrorResponse(ctx, errors.NewForbiddenError("account not authorized to deprovision users"))
	}

	identity, err := c.app.UserService().BanUser(ctx, ctx.Username)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":      err,
			"username": ctx.Username,
		}, "unable to ban user")
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	log.Info(ctx, map[string]interface{}{
		"username": ctx.Username,
	}, "user banned")

	return ctx.OK(ConvertToAppUser(ctx.RequestData, &identity.User, identity, true))
}

// Deprovision runs the deprovision action.
// DEPRECATED: see `Ban`
func (c *NamedusersController) Deprovision(ctx *app.DeprovisionNamedusersContext) error {
	// internally forward to the `/ban` endpoint method of this controller
	return c.Ban(&app.BanNamedusersContext{
		Context:      ctx.Context,
		RequestData:  ctx.RequestData,
		ResponseData: ctx.ResponseData,
		Username:     ctx.Username,
	})
}

// Deactivate runs the deactivate action.
func (c *NamedusersController) Deactivate(ctx *app.DeactivateNamedusersContext) error {
	isSvcAccount := token.IsSpecificServiceAccount(ctx, token.OnlineRegistration)
	if !isSvcAccount {
		log.Error(ctx, nil, "the account is not an authorized service account allowed to deprovision users")
		return jsonapi.JSONErrorResponse(ctx, errors.NewForbiddenError("account not authorized to deprovision users"))
	}

	identity, err := c.app.UserService().DeactivateUser(ctx, ctx.Username)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":      err,
			"username": ctx.Username,
		}, "error occurred while deactivating user")
		if notFound, _ := errors.IsNotFoundError(err); !notFound {
			return jsonapi.JSONErrorResponse(ctx, err)
		}
		// Ignore notFound error. If user has not found then we don't want the reg-app keep trying to deactivate it in auth.
		// We can add some dummy Identity in response here
		identity = &repository.Identity{}
	} else {
		log.Info(ctx, map[string]interface{}{
			"username": ctx.Username,
		}, "user deactivated")
	}

	return ctx.OK(ConvertToAppUser(ctx.RequestData, &identity.User, identity, true))
}
