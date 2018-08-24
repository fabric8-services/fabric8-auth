package controller

import (
	"fmt"
	"golang.org/x/oauth2"

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
)

type LoginConfiguration interface {
	login.Configuration
	GetOAuthServiceEndpointAuth(*goa.RequestData) (string, error)
	GetOAuthServiceURL() string
	GetOAuthServiceRealm() string
	GetPublicOauthClientID() string
	GetServiceAccounts() map[string]configuration.ServiceAccount
}

// LoginController implements the login resource.
type LoginController struct {
	*goa.Controller
	Auth          login.OAuthService
	TokenManager  token.Manager
	Configuration LoginConfiguration
}

// NewLoginController creates a login controller.
func NewLoginController(service *goa.Service, auth *login.OAuthServiceProvider, tokenManager token.Manager, configuration LoginConfiguration) *LoginController {
	return &LoginController{Controller: service.NewController("login"), Auth: auth, TokenManager: tokenManager, Configuration: configuration}
}

// Login runs the login action.
func (c *LoginController) Login(ctx *app.LoginLoginContext) error {
	authEndpoint, err := c.Configuration.GetOAuthServiceEndpointAuth(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Unable to get OAuth Service Auth endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get OAuth Service Auth endpoint URL")))
	}

	tokenEndpoint, err := c.Configuration.GetOAuthServiceEndpointToken(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Unable to get OAuth Service token endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get OAuth Service token endpoint URL")))
	}
	if ctx.Scope != nil {
		authEndpoint = fmt.Sprintf("%s?scope=%s", authEndpoint, *ctx.Scope) // Offline token
	}
	oauth := &oauth2.Config{
		ClientID:     c.Configuration.GetOAuthServiceClientID(),
		ClientSecret: c.Configuration.GetOAuthServiceSecret(),
		Scopes:       []string{"user:email"},
		Endpoint:     oauth2.Endpoint{AuthURL: authEndpoint, TokenURL: tokenEndpoint},
		RedirectURL:  rest.AbsoluteURL(ctx.RequestData, "/api/login", nil),
	}

	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	return c.Auth.Login(ctx, oauth, c.Configuration)
}
