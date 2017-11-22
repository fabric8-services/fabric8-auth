package controller

import (
	"fmt"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/configuration"
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

type LoginConfiguration interface {
	GetKeycloakEndpointAuth(*goa.RequestData) (string, error)
	GetKeycloakEndpointToken(*goa.RequestData) (string, error)
	GetKeycloakAccountEndpoint(req *goa.RequestData) (string, error)
	GetKeycloakEndpointBroker(*goa.RequestData) (string, error)
	GetKeycloakEndpointEntitlement(*goa.RequestData) (string, error)
	GetKeycloakClientID() string
	GetKeycloakSecret() string
	IsPostgresDeveloperModeEnabled() bool
	GetOpenShiftClientApiUrl() string
	GetKeycloakTestUserName() string
	GetKeycloakTestUserSecret() string
	GetKeycloakTestUser2Name() string
	GetKeycloakTestUser2Secret() string
	GetValidRedirectURLs() string
	GetHeaderMaxLength() int64
	GetNotApprovedRedirect() string
	GetWITURL(*goa.RequestData) (string, error)
	GetKeycloakURL() string
	GetKeycloakRealm() string
	GetServiceAccounts() map[string]configuration.ServiceAccount
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

	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	return c.Auth.Perform(ctx, oauth, c.Configuration)
}
