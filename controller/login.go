package controller

import (
	"fmt"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-auth/token"

	client "github.com/fabric8-services/fabric8-auth/client"
	"github.com/goadesign/goa"
)

type LoginConfiguration interface {
	login.Configuration
	GetKeycloakEndpointAuth(*goa.RequestData) (string, error)
	GetKeycloakURL() string
	GetKeycloakRealm() string
	GetPublicOauthClientID() string
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

	oauthIdentityProvider := login.NewIdentityProvider(c.Configuration)
	oauthIdentityProvider.RedirectURL = rest.AbsoluteURL(ctx.RequestData, client.LoginLoginPath(), nil)
	if ctx.Scope != nil {
		oauthIdentityProvider.Endpoint.AuthURL = fmt.Sprintf("%s?scope=%s", oauthIdentityProvider.Endpoint.AuthURL, *ctx.Scope) // Offline token
	}

	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	return c.Auth.Login(ctx, oauthIdentityProvider, c.Configuration)
}
