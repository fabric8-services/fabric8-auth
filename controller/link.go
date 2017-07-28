package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/provider"
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
	GithubService provider.GithubLoginService
}

// NewLinkController creates a link controller.
func NewLinkController(service *goa.Service, auth *login.KeycloakOAuthProvider, tokenManager token.Manager, configuration LoginConfiguration, githubLoginService provider.GithubLoginService) *LinkController {
	return &LinkController{Controller: service.NewController("link"), Auth: auth, TokenManager: tokenManager, Configuration: configuration, GithubService: githubLoginService}
}

// Link links identity provider(s) to the user's account
func (c *LinkController) Link(ctx *app.LinkLinkContext) error {
	// TODO: Write code in a generic way to use the appropriate oauth
	// service based on provider
	return c.GithubService.Perform(ctx)
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
	whitelist, err := c.Configuration.GetValidRedirectURLs(ctx.RequestData)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}

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
