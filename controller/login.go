package controller

import (
	"context"
	"time"

	"golang.org/x/oauth2"

	"net/http"
	"net/url"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/auth"
	"github.com/fabric8-services/fabric8-auth/rest"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/test"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/goadesign/goa"
	errs "github.com/pkg/errors"
)

type loginConfiguration interface {
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
	GetNotApprovedRedirect() string
}

// LoginController implements the login resource.
type LoginController struct {
	*goa.Controller
	auth          login.KeycloakOAuthService
	tokenManager  token.Manager
	configuration loginConfiguration
}

// NewLoginController creates a login controller.
func NewLoginController(service *goa.Service, auth *login.KeycloakOAuthProvider, tokenManager token.Manager, configuration loginConfiguration) *LoginController {
	return &LoginController{Controller: service.NewController("login"), auth: auth, tokenManager: tokenManager, configuration: configuration}
}

// Authorize runs the authorize action.
func (c *LoginController) Authorize(ctx *app.AuthorizeLoginContext) error {
	authEndpoint, err := c.configuration.GetKeycloakEndpointAuth(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Unable to get Keycloak auth endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get Keycloak auth endpoint URL")))
	}

	tokenEndpoint, err := c.configuration.GetKeycloakEndpointToken(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Unable to get Keycloak token endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get Keycloak token endpoint URL")))
	}

	entitlementEndpoint, err := c.configuration.GetKeycloakEndpointEntitlement(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Unable to get Keycloak entitlement endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get Keycloak entitlement endpoint URL")))
	}

	brokerEndpoint, err := c.configuration.GetKeycloakEndpointBroker(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Unable to get Keycloak broker endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get Keycloak broker endpoint URL")))
	}
	profileEndpoint, err := c.configuration.GetKeycloakAccountEndpoint(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to get Keycloak account endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}
	whitelist, err := c.configuration.GetValidRedirectURLs(ctx.RequestData)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}

	oauth := &oauth2.Config{
		ClientID:     c.configuration.GetKeycloakClientID(),
		ClientSecret: c.configuration.GetKeycloakSecret(),
		Scopes:       []string{"user:email"},
		Endpoint:     oauth2.Endpoint{AuthURL: authEndpoint, TokenURL: tokenEndpoint},
		RedirectURL:  rest.AbsoluteURL(ctx.RequestData, "/api/login/authorize"),
	}

	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	return c.auth.Perform(ctx, oauth, brokerEndpoint, entitlementEndpoint, profileEndpoint, whitelist, c.configuration.GetNotApprovedRedirect())
}

// Refresh obtain a new access token using the refresh token.
func (c *LoginController) Refresh(ctx *app.RefreshLoginContext) error {
	refreshToken := ctx.Payload.RefreshToken
	if refreshToken == nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("refresh_token", nil).Expected("not nil"))
	}

	client := &http.Client{Timeout: 10 * time.Second}
	endpoint, err := c.configuration.GetKeycloakEndpointToken(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Unable to get Keycloak token endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get Keycloak token endpoint URL")))
	}
	res, err := client.PostForm(endpoint, url.Values{
		"client_id":     {c.configuration.GetKeycloakClientID()},
		"client_secret": {c.configuration.GetKeycloakSecret()},
		"refresh_token": {*refreshToken},
		"grant_type":    {"refresh_token"},
	})
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "error when obtaining token")))
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case 200:
		// OK
	case 401:
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError(res.Status+" "+rest.ReadBody(res.Body)))
	case 400:
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError(res.Status+" "+rest.ReadBody(res.Body)))
	default:
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.New(res.Status+" "+rest.ReadBody(res.Body))))
	}

	token, err := auth.ReadToken(ctx, res)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	entitlementEndpoint, err := c.configuration.GetKeycloakEndpointEntitlement(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Unable to get Keycloak token endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get Keycloak token endpoint URL")))
	}

	rpt, err := auth.GetEntitlement(ctx, entitlementEndpoint, nil, *token.AccessToken)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "failed to obtain entitlement during login")
		return jsonapi.JSONErrorResponse(ctx, goa.ErrInternal(err.Error()))
	}
	if rpt != nil && int64(len(*rpt)) <= c.configuration.GetHeaderMaxLength() {
		// If the rpt token is not too long for using it as a Bearer in http requests because of header size limit
		// the swap access token for the rpt token which contains all resources available to the user
		token.AccessToken = rpt
	}

	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	return ctx.OK(convertToken(*token))
}

func convertToken(token auth.Token) *app.AuthToken {
	return &app.AuthToken{Token: &app.TokenData{
		AccessToken:      token.AccessToken,
		ExpiresIn:        token.ExpiresIn,
		NotBeforePolicy:  token.NotBeforePolicy,
		RefreshExpiresIn: token.RefreshExpiresIn,
		RefreshToken:     token.RefreshToken,
		TokenType:        token.TokenType,
	}}
}

// Link links identity provider(s) to the user's account
func (c *LoginController) Link(ctx *app.LinkLoginContext) error {

	/*

		We'll keep the Link API endpoint as is but will modify the behaviour to not use
		KC linking.

		- Based on the IDP passed as req param ( "github", "OSO-1" , "OSO-2" ) , pick up the client id and secret
		from the config framework and initiate an OAuth flow.

		- Handle the 2 step auth ( code + token exchange ) the same way we do for login using KC ,

		- After a successful auth, save the token.

	*/

	brokerEndpoint, err := c.configuration.GetKeycloakEndpointBroker(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Unable to get Keycloak broker endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get Keycloak broker endpoint URL")))
	}
	clientID := c.configuration.GetKeycloakClientID()
	whitelist, err := c.configuration.GetValidRedirectURLs(ctx.RequestData)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}

	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	return c.auth.Link(ctx, brokerEndpoint, clientID, whitelist)
}

// We can do away with /LinkSession because we anyway don't do auto-linking right now
// https://github.com/alexeykazakov/fabric8-wit/commit/1cede472e36dfc85c9bdf43c9629dff2dbec3c29

// Linksession links identity provider(s) to the user's account
func (c *LoginController) Linksession(ctx *app.LinksessionLoginContext) error {
	brokerEndpoint, err := c.configuration.GetKeycloakEndpointBroker(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Unable to get Keycloak broker endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get Keycloak broker endpoint URL")))
	}
	clientID := c.configuration.GetKeycloakClientID()
	whitelist, err := c.configuration.GetValidRedirectURLs(ctx.RequestData)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}

	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	return c.auth.LinkSession(ctx, brokerEndpoint, clientID, whitelist)
}

// Linkcallback redirects to original referel when Identity Provider account are linked to the user account
func (c *LoginController) Linkcallback(ctx *app.LinkcallbackLoginContext) error {
	brokerEndpoint, err := c.configuration.GetKeycloakEndpointBroker(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Unable to get Keycloak broker endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get Keycloak broker endpoint URL ")))
	}
	clientID := c.configuration.GetKeycloakClientID()

	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	return c.auth.LinkCallback(ctx, brokerEndpoint, clientID)
}

// Generate obtain the access token from Keycloak for the test user
func (c *LoginController) Generate(ctx *app.GenerateLoginContext) error {
	var tokens app.AuthTokenCollection

	tokenEndpoint, err := c.configuration.GetKeycloakEndpointToken(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to get Keycloak token endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get Keycloak token endpoint URL")))
	}

	testuser, err := GenerateUserToken(ctx, tokenEndpoint, c.configuration, c.configuration.GetKeycloakTestUserName(), c.configuration.GetKeycloakTestUserSecret())
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to get Generate User token")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to generate test token ")))
	}
	// Creates the testuser user and identity if they don't yet exist
	profileEndpoint, err := c.configuration.GetKeycloakAccountEndpoint(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to get Keycloak account endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}
	c.auth.CreateOrUpdateKeycloakUser(*testuser.Token.AccessToken, ctx, profileEndpoint)
	tokens = append(tokens, testuser)

	testuser, err = GenerateUserToken(ctx, tokenEndpoint, c.configuration, c.configuration.GetKeycloakTestUser2Name(), c.configuration.GetKeycloakTestUser2Secret())
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to generate test token")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to generate test token")))
	}
	// Creates the testuser2 user and identity if they don't yet exist
	_, _, err = c.auth.CreateOrUpdateKeycloakUser(*testuser.Token.AccessToken, ctx, profileEndpoint)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to persist user properly")
	}
	tokens = append(tokens, testuser)

	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	return ctx.OK(tokens)
}

// GenerateUserToken obtains the access token from Keycloak for the user
func GenerateUserToken(ctx context.Context, tokenEndpoint string, configuration loginConfiguration, username string, userSecret string) (*app.AuthToken, error) {
	if !configuration.IsPostgresDeveloperModeEnabled() {
		log.Error(ctx, map[string]interface{}{
			"method": "Generate",
		}, "Postgres developer mode not enabled")
		return nil, errors.NewInternalError(ctx, errs.New("postgres developer mode is not enabled"))
	}

	var scopes []account.Identity
	scopes = append(scopes, test.TestIdentity)
	scopes = append(scopes, test.TestObserverIdentity)

	client := &http.Client{Timeout: 10 * time.Second}

	res, err := client.PostForm(tokenEndpoint, url.Values{
		"client_id":     {configuration.GetKeycloakClientID()},
		"client_secret": {configuration.GetKeycloakSecret()},
		"username":      {username},
		"password":      {userSecret},
		"grant_type":    {"password"},
	})
	if err != nil {
		return nil, errors.NewInternalError(ctx, errs.Wrap(err, "error when obtaining token"))
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		log.Error(ctx, map[string]interface{}{
			"response_status": res.Status,
			"response_body":   rest.ReadBody(res.Body),
		}, "unable to obtain token")
		return nil, errors.NewInternalError(ctx, errs.Errorf("unable to obtain toke. Response status: %s. Responce body: %s", res.Status, rest.ReadBody(res.Body)))
	}
	token, err := auth.ReadToken(ctx, res)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"token_endpoint": res,
			"err":            err,
		}, "Error when unmarshal json with access token")
		return nil, errors.NewInternalError(ctx, errs.Wrap(err, "error when unmarshal json with access token"))
	}

	return convertToken(*token), nil
}
