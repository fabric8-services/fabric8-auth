package controller

import (
	"context"
	"net/url"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/goadesign/goa"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
)

// LogoutController implements the logout resource.
type LogoutController struct {
	*goa.Controller
	app application.Application
}

// Common context interface for both logout endpoints
type LogoutContext interface {
	context.Context
	TemporaryRedirect() error
	InternalServerError(*app.JSONAPIErrors) error
}

// NewLogoutController creates a logout controller.
func NewLogoutController(service *goa.Service, app application.Application) *LogoutController {
	return &LogoutController{Controller: service.NewController("LogoutController"), app: app}
}

// Logout runs the logout action.
func (c *LogoutController) Logout(ctx *app.LogoutLogoutContext) error {
	return c.doLogout(ctx, ctx.Redirect, ctx.Referer, ctx.ResponseData, nil)
}

// Logoutv2 is a secured logout endpoint that also invalidates all of the user's tokens
func (c *LogoutController) Logoutv2(ctx *app.Logoutv2LogoutContext) error {
	token := goajwt.ContextJWT(ctx)
	if token == nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("no token in request"))
	}

	tokenString := token.Raw
	return c.doLogout(ctx, ctx.Redirect, ctx.Referer, ctx.ResponseData, &tokenString)
}

// doLogout performs the logout action, optionally with the user's token string in order to invalidate all the
// user's tokens
func (c *LogoutController) doLogout(ctx LogoutContext, redirect *string, referrer *string, responseData *goa.ResponseData, tokenString *string) error {
	if redirect == nil {
		if referrer == nil {
			log.Error(ctx, nil, "Failed to logout. Referer Header and redirect param are both empty.")
			return jsonapi.JSONErrorResponse(ctx, goa.ErrBadRequest("referer Header and redirect param are both empty (at least one should be specified)"))
		}
		redirect = referrer
	}
	log.Debug(ctx, map[string]interface{}{
		"referrer": referrer,
		"redirect": *redirect,
	}, "Got Request to logout!")

	redirectURL, err := url.Parse(*redirect)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"redirect_url": *redirect,
			"err":          err,
		}, "Failed to logout. Unable to parse provided redirect url.")
		return jsonapi.JSONErrorResponse(ctx, goa.ErrBadRequest(err.Error()))
	}
	log.Debug(ctx, map[string]interface{}{
		"redirect_url": *redirectURL,
		"err":          err,
	}, "parsed provided redirect url.")

	logoutRedirect, err := c.app.LogoutService().Logout(ctx, tokenString, redirectURL.String())
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"redirect_url": redirectURL.String(),
			"err":          err,
		}, "Failed to logout.")
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	responseData.Header().Set("Cache-Control", "no-cache")
	responseData.Header().Set("Location", logoutRedirect)
	return ctx.TemporaryRedirect()
}