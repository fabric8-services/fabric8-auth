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

	if ctx.State == nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("state", "nil").Expected("State"))
	}

	if ctx.Code == nil {
		if ctx.ClientID == nil {
			return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("client_id", "nil").Expected("Service Account ID"))
		}
		if ctx.RedirectURI == nil {
			return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("redirect_uri", "nil").Expected("Redirect URI"))
		}
		if ctx.ResponseType == nil {
			return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("response_type", "nil").Expected("Response Type"))
		}
		if ctx.Scope == nil {
			return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("scope", "nil").Expected("Scope"))
		}

		_, found := c.Configuration.GetServiceAccounts()[*ctx.ClientID]
		if !found {
			log.Error(ctx, map[string]interface{}{
				"client_id": *ctx.ClientID,
			}, "Unknown Service Account ID")
			return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("invalid Service Account ID"))
		}

	}
	authEndpoint, err := c.Configuration.GetKeycloakEndpointAuth(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Unable to get Keycloak Auth endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get Keycloak Auth endpoint URL")))
	}

	tokenEndpoint, err := c.Configuration.GetKeycloakEndpointToken(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Unable to get Keycloak token endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get Keycloak token endpoint URL")))
	}
	if ctx.Scope != nil {
		authEndpoint = fmt.Sprintf("%s?scope=%s", authEndpoint, *ctx.Scope)
	}

	oauth := &oauth2.Config{
		ClientID:     c.Configuration.GetKeycloakClientID(),
		ClientSecret: c.Configuration.GetKeycloakSecret(),
		Scopes:       []string{"user:email"},
		Endpoint:     oauth2.Endpoint{AuthURL: authEndpoint, TokenURL: tokenEndpoint},
		RedirectURL:  rest.AbsoluteURL(ctx.RequestData, "/api/authorize"),
	}

	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	return c.Auth.PerformAuthorize(ctx, oauth, c.Configuration)
}
