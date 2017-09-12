package controller

import (
	"golang.org/x/oauth2"

	"github.com/fabric8-services/fabric8-auth/rest"

	"fmt"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/goadesign/goa"
	errs "github.com/pkg/errors"
)

type LoginConfiguration interface {
	GetKeycloakEndpointAuth(*goa.RequestData) (string, error)
	GetKeycloakEndpointToken(*goa.RequestData) (string, error)
	GetKeycloakAccountEndpoint(req *goa.RequestData) (string, error)
	GetKeycloakEndpointBroker(*goa.RequestData) (string, error)
	GetKeycloakEndpointEntitlement(*goa.RequestData) (string, error)
	GetKeycloakClientID() string
	GetKeycloakSecret() string
	IsPostgresDeveloperModeEnabled() bool
	GetKeycloakTestUserName() string
	GetKeycloakTestUserSecret() string
	GetKeycloakTestUser2Name() string
	GetKeycloakTestUser2Secret() string
	GetValidRedirectURLs(*goa.RequestData) (string, error)
	GetHeaderMaxLength() int64
	GetAuthNotApprovedRedirect() string
	GetWITEndpoint(*goa.RequestData) (string, error)
}

// LoginController implements the login resource.
type LoginController struct {
	*goa.Controller
	Auth          login.KeycloakOAuthService
	TokenManager  token.Manager
	Configuration LoginConfiguration
}

// NewLoginController creates a login controller.
func NewLoginController(service *goa.Service, auth *login.KeycloakOAuthProvider, tokenManager token.Manager, configuration LoginConfiguration) *LoginController {
	return &LoginController{Controller: service.NewController("login"), Auth: auth, TokenManager: tokenManager, Configuration: configuration}
}

// Login runs the login action.
func (c *LoginController) Login(ctx *app.LoginLoginContext) error {
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

	entitlementEndpoint, err := c.Configuration.GetKeycloakEndpointEntitlement(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Unable to get Keycloak entitlement endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get Keycloak entitlement endpoint URL")))
	}

	brokerEndpoint, err := c.Configuration.GetKeycloakEndpointBroker(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Unable to get Keycloak broker endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get Keycloak broker endpoint URL")))
	}
	profileEndpoint, err := c.Configuration.GetKeycloakAccountEndpoint(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to get Keycloak account endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}
	whitelist, err := c.Configuration.GetValidRedirectURLs(ctx.RequestData)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}

	if ctx.Scope != nil {
		authEndpoint = fmt.Sprintf("%s?scope=%s", authEndpoint, *ctx.Scope) // Offline token
	}
	oauth := &oauth2.Config{
		ClientID:     c.Configuration.GetKeycloakClientID(),
		ClientSecret: c.Configuration.GetKeycloakSecret(),
		Scopes:       []string{"user:email"},
		Endpoint:     oauth2.Endpoint{AuthURL: authEndpoint, TokenURL: tokenEndpoint},
		RedirectURL:  rest.AbsoluteURL(ctx.RequestData, "/api/login"),
	}
	remoteWITUserProfile, err := c.Configuration.GetWITEndpoint(ctx.RequestData)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}

	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	return c.Auth.Perform(ctx, oauth, brokerEndpoint, entitlementEndpoint, profileEndpoint, whitelist, c.Configuration.GetAuthNotApprovedRedirect(), remoteWITUserProfile)
}
