package controller

import (
	"fmt"

	"github.com/fabric8-services/fabric8-auth/app"
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

func NewAuthorizeController(service *goa.Service, auth *login.KeycloakOAuthProvider, tokenManager token.Manager, configuration LoginConfiguration) *AuthorizeController {
	return &AuthorizeController{Controller: service.NewController("AuthorizeController"), Auth: auth, TokenManager: tokenManager, Configuration: configuration}
}

// Authorize runs the authorize action.
func (c *AuthorizeController) Authorize(ctx *app.AuthorizeAuthorizeContext) error {

	var scope []string

	if ctx.Scope == nil {
		scope = []string{"user:email"}
	} else {
		scope = []string{*ctx.Scope}
	}

	_, found := c.Configuration.GetServiceAccounts()[ctx.ClientID]
	if !found {
		log.Error(ctx, map[string]interface{}{
			"client_id": ctx.ClientID,
		}, "unknown service account id")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("invalid service account id"))
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
		RedirectURL:  rest.AbsoluteURL(ctx.RequestData, "/api/authorize/callback"),
	}

	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	return c.Auth.PerformAuthorize(ctx, oauth, c.Configuration)
}

// Callback takes care of Authorize callback
func (c *AuthorizeController) Callback(ctx *app.CallbackAuthorizeContext) error {

	referrerURL, err := c.Auth.VerifyState(ctx, ctx.State.String(), ctx.Code)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	ctx.ResponseData.Header().Set(
		"Location",
		fmt.Sprintf("%s?code=%s&state=%s", referrerURL.String(), ctx.Code, ctx.State))
	return ctx.TemporaryRedirect()
}
