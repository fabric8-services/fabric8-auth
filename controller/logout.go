package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/goadesign/goa"
	"net/url"
)

// LogoutController implements the logout resource.
type LogoutController struct {
	*goa.Controller
	app application.Application
}

// NewLogoutController creates a logout controller.
func NewLogoutController(service *goa.Service, app application.Application) *LogoutController {
	return &LogoutController{Controller: service.NewController("LogoutController"), app: app}
}

// Logout runs the logout action.
func (c *LogoutController) Logout(ctx *app.LogoutLogoutContext) error {
	redirect := ctx.Redirect
	referrer := ctx.RequestData.Header.Get("Referer")
	if redirect == nil {
		if referrer == "" {
			log.Error(ctx, nil, "Failed to logout. Referer Header and redirect param are both empty.")
			return jsonapi.JSONErrorResponse(ctx, goa.ErrBadRequest("referer Header and redirect param are both empty (at least one should be specified)"))
		}
		redirect = &referrer
	}
	log.Info(ctx, map[string]interface{}{
		"referrer": referrer,
		"redirect": redirect,
	}, "Got Request to logout!")

	redirectURL, err := url.Parse(*redirect)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"redirect_url": redirectURL,
			"err":          err,
		}, "Failed to logout. Unable to parse redirect url.")
		return jsonapi.JSONErrorResponse(ctx, goa.ErrBadRequest(err.Error()))
	}

	err = c.app.LogoutService().Logout(ctx, redirectURL.String())
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"redirect_url": redirectURL,
			"err":          err,
		}, "Failed to logout.")
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	ctx.ResponseData.Header().Set("Location", redirectURL.String())
	return ctx.TemporaryRedirect()
}
