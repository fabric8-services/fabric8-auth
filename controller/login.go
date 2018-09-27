package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/client"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
)

// LoginController implements the login resource.
type LoginController struct {
	*goa.Controller
	app          application.Application
	Auth         login.KeycloakOAuthService
	TokenManager token.Manager
}

// NewLoginController creates a login controller.
func NewLoginController(service *goa.Service, app application.Application, auth *login.KeycloakOAuthProvider, tokenManager token.Manager) *LoginController {
	return &LoginController{
		Controller:   service.NewController("login"),
		app:          app,
		Auth:         auth,
		TokenManager: tokenManager}
}

// Login runs the login action.
func (c *LoginController) Login(ctx *app.LoginLoginContext) error {
	// Generate a new unique state value
	state := uuid.NewV4().String()

	// Get the URL of the callback endpoint, the client will be redirected here after being redirected to the authentication provider
	callbackURL := rest.AbsoluteURL(ctx.RequestData, client.CallbackLoginPath(), nil)

	redirectURL, err := c.app.AuthenticationProviderService().GenerateAuthCodeURL(ctx, ctx.Redirect, ctx.APIClient,
		&state, nil, ctx.RequestData.Header.Get("Referer"), callbackURL)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	ctx.ResponseData.Header().Set("Location", *redirectURL)
	return ctx.TemporaryRedirect()
}

func (c *LoginController) Callback(ctx *app.CallbackLoginContext) error {

	state := ctx.Params.Get("state")
	code := ctx.Params.Get("code")

	err := c.app.LoginService().Callback(ctx, state, code)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
}
