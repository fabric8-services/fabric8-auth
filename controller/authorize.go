package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/client"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/goadesign/goa"
	errs "github.com/pkg/errors"
	"golang.org/x/oauth2"
)

// AuthorizeController implements the authorize resource.
type AuthorizeController struct {
	*goa.Controller
	Auth          login.KeycloakOAuthService
	TokenManager  token.Manager
	Configuration LoginConfiguration
}

// NewAuthorizeController returns a new AuthorizeController
func NewAuthorizeController(service *goa.Service, auth *login.KeycloakOAuthProvider, tokenManager token.Manager, configuration LoginConfiguration) *AuthorizeController {
	return &AuthorizeController{Controller: service.NewController("AuthorizeController"), Auth: auth, TokenManager: tokenManager, Configuration: configuration}
}

// Authorize runs the authorize action of /api/authorize endpoint.
func (c *AuthorizeController) Authorize(ctx *app.AuthorizeAuthorizeContext) error {

	var scope []string

	if ctx.Scope == nil {
		scope = []string{"user:email"}
	} else {
		scope = []string{*ctx.Scope}
	}

	// Default value of this public client id is set to "740650a2-9c44-4db5-b067-a3d1b2cd2d01"
	if ctx.ClientID != c.Configuration.GetPublicOauthClientID() {
		log.Error(ctx, map[string]interface{}{
			"client_id": ctx.ClientID,
		}, "unknown oauth client id")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("invalid oauth client id"))
	}

	authEndpoint, err := c.Configuration.GetKeycloakEndpointAuth(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to get keycloak auth endpoint url")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get keycloak auth endpoint url")))
	}

	tokenEndpoint, err := c.Configuration.GetKeycloakEndpointToken(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to get keycloak token endpoint url")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get keycloak token endpoint url")))
	}

	oauth := &oauth2.Config{
		ClientID:     c.Configuration.GetKeycloakClientID(),
		ClientSecret: c.Configuration.GetKeycloakSecret(),
		Scopes:       scope,
		Endpoint:     oauth2.Endpoint{AuthURL: authEndpoint, TokenURL: tokenEndpoint},
		RedirectURL:  rest.AbsoluteURL(ctx.RequestData, client.CallbackAuthorizePath()),
	}

	redirectTo, err := c.Auth.AuthCodeURL(ctx, &ctx.RedirectURI, ctx.APIClient, &ctx.State, ctx.RequestData, oauth, c.Configuration)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	ctx.ResponseData.Header().Set("Location", *redirectTo)
	return ctx.TemporaryRedirect()
}

// Callback takes care of Authorize callback
func (c *AuthorizeController) Callback(ctx *app.CallbackAuthorizeContext) error {
	redirectTo, err := c.Auth.AuthCodeCallback(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	ctx.ResponseData.Header().Set("Location", *redirectTo)
	return ctx.TemporaryRedirect()
}
