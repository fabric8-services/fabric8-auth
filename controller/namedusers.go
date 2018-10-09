package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	accountservice "github.com/fabric8-services/fabric8-auth/authentication/account/service"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/sentry"
	"github.com/fabric8-services/fabric8-auth/token"

	"github.com/goadesign/goa"
)

// NamedusersController implements the namedusers resource.
type NamedusersController struct {
	*goa.Controller
	app           application.Application
	config        UsersControllerConfiguration
	tenantService accountservice.TenantService
}

// NewNamedusersController creates a namedusers controller.
func NewNamedusersController(service *goa.Service, app application.Application, config UsersControllerConfiguration, tenantService accountservice.TenantService) *NamedusersController {
	return &NamedusersController{
		Controller:    service.NewController("NamedusersController"),
		app:           app,
		config:        config,
		tenantService: tenantService,
	}
}

// Deprovision runs the deprovision action.
func (c *NamedusersController) Deprovision(ctx *app.DeprovisionNamedusersContext) error {
	isSvcAccount := token.IsSpecificServiceAccount(ctx, token.OnlineRegistration)
	if !isSvcAccount {
		log.Error(ctx, nil, "the account is not an authorized service account allowed to deprovision users")
		return jsonapi.JSONErrorResponse(ctx, errors.NewForbiddenError("account not authorized to deprovision users"))
	}

	identity, err := c.app.UserService().DeprovisionUser(ctx, ctx.Username)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":      err,
			"username": ctx.Username,
		}, "unable to deprovision user")
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	// Delete tenant (if access to tenant service is configured/enabled)
	if c.tenantService != nil {
		err := c.tenantService.Delete(ctx, identity.ID)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"err":         err,
				"identity_id": identity.ID,
				"username":    ctx.Username,
			}, "unable to delete tenant when deprovisioning user")
			sentry.Sentry().CaptureError(ctx, err)
			// Just log the error and proceed
		}
	}

	return ctx.OK(ConvertToAppUser(ctx.RequestData, &identity.User, identity, true))
}
