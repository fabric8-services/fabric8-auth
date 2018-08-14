package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/goadesign/goa"
	errs "github.com/pkg/errors"
)

type logoutConfiguration interface {
	GetOAuthServiceEndpointLogout(*goa.RequestData) (string, error)
	GetValidRedirectURLs() string
}

// LogoutController implements the logout resource.
type LogoutController struct {
	*goa.Controller
	logoutService login.LogoutService
	configuration logoutConfiguration
}

// NewLogoutController creates a logout controller.
func NewLogoutController(service *goa.Service, logoutService *login.OAuthLogoutService, configuration logoutConfiguration) *LogoutController {
	return &LogoutController{Controller: service.NewController("LogoutController"), logoutService: logoutService, configuration: configuration}
}

// Logout runs the logout action.
func (c *LogoutController) Logout(ctx *app.LogoutLogoutContext) error {
	logoutEndpoint, err := c.configuration.GetOAuthServiceEndpointLogout(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Unable to get oauth service logout endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get oauth service logout endpoint URL")))
	}
	whitelist := c.configuration.GetValidRedirectURLs()

	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	return c.logoutService.Logout(ctx, logoutEndpoint, whitelist)
}
