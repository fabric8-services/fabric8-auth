package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/client"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"

	"github.com/goadesign/goa"
)

// AuthorizeController implements the authorize resource.
type AuthorizeController struct {
	*goa.Controller
	app application.Application
}

// NewAuthorizeController returns a new AuthorizeController
func NewAuthorizeController(service *goa.Service, app application.Application) *AuthorizeController {
	return &AuthorizeController{Controller: service.NewController("AuthorizeController"), app: app}
}

// Authorize runs the authorize action of /api/authorize endpoint.
func (c *AuthorizeController) Authorize(ctx *app.AuthorizeAuthorizeContext) error {

	var scopes []string

	if ctx.Scope != nil {
		scopes = []string{*ctx.Scope}
	}

	// Default value of this public client id is set to "740650a2-9c44-4db5-b067-a3d1b2cd2d01"
	if ctx.ClientID != c.Configuration.GetPublicOauthClientID() {
		log.Error(ctx, map[string]interface{}{
			"client_id": ctx.ClientID,
		}, "unknown oauth client id")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("invalid oauth client id"))
	}

	// Get the URL of the callback endpoint, the client will be redirected here after being redirected to the authentication provider
	callbackURL := rest.AbsoluteURL(ctx.RequestData, client.CallbackAuthorizePath(), nil)

	redirectTo, err := c.app.AuthenticationProviderService().GenerateAuthCodeURL(ctx, &ctx.RedirectURI, ctx.APIClient,
		&ctx.State, scopes, ctx.ResponseMode, ctx.RequestData.Header.Get("Referer"), callbackURL)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	ctx.ResponseData.Header().Set("Location", *redirectTo)
	return ctx.TemporaryRedirect()
}

// Callback takes care of Authorize callback
func (c *AuthorizeController) Callback(ctx *app.CallbackAuthorizeContext) error {

	redirectTo, err := c.app.AuthenticationProviderService().AuthorizeCallback(ctx, ctx.State, ctx.Code)

	//redirectTo, err := c.Auth.AuthCodeCallback(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	ctx.ResponseData.Header().Set("Location", *redirectTo)
	return ctx.TemporaryRedirect()
}
