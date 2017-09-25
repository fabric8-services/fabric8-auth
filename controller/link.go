package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/goadesign/goa"
	errs "github.com/pkg/errors"
)

// LinkController implements the link resource.
type LinkController struct {
	*goa.Controller
	Auth          login.KeycloakOAuthService
	TokenManager  token.Manager
	Configuration LoginConfiguration
}

// NewLinkController creates a link controller.
func NewLinkController(service *goa.Service, auth *login.KeycloakOAuthProvider, tokenManager token.Manager, configuration LoginConfiguration) *LinkController {
	return &LinkController{Controller: service.NewController("link"), Auth: auth, TokenManager: tokenManager, Configuration: configuration}
}

// Link links identity provider(s) to the user's account
func (c *LinkController) Link(ctx *app.LinkLinkContext) error {
	brokerEndpoint, err := c.Configuration.GetKeycloakEndpointBroker(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Unable to get Keycloak broker endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get Keycloak broker endpoint URL")))
	}
	clientID := c.Configuration.GetKeycloakClientID()
	whitelist := c.Configuration.GetValidRedirectURLs()

	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	return c.Auth.Link(ctx, brokerEndpoint, clientID, whitelist)
}

// Session links identity provider(s) to the user's account
func (c *LinkController) Session(ctx *app.SessionLinkContext) error {
	brokerEndpoint, err := c.Configuration.GetKeycloakEndpointBroker(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Unable to get Keycloak broker endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get Keycloak broker endpoint URL")))
	}
	clientID := c.Configuration.GetKeycloakClientID()
	whitelist := c.Configuration.GetValidRedirectURLs()

	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	return c.Auth.LinkSession(ctx, brokerEndpoint, clientID, whitelist)
}

// Callback redirects to original referel when Identity Provider account are linked to the user account
func (c *LinkController) Callback(ctx *app.CallbackLinkContext) error {
	brokerEndpoint, err := c.Configuration.GetKeycloakEndpointBroker(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Unable to get Keycloak broker endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get Keycloak broker endpoint URL ")))
	}
	clientID := c.Configuration.GetKeycloakClientID()

	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	return c.Auth.LinkCallback(ctx, brokerEndpoint, clientID)
}
