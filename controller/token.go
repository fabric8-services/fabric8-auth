package controller

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/client"
	uuid "github.com/satori/go.uuid"

	"github.com/fabric8-services/fabric8-auth/token/keycloak"
	"github.com/fabric8-services/fabric8-auth/token/provider"

	"net/http"
	"net/url"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-auth/test"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/fabric8-services/fabric8-auth/token/link"

	"strings"

	"github.com/goadesign/goa"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	errs "github.com/pkg/errors"
)

// TokenController implements the login resource.
type TokenController struct {
	*goa.Controller
	db                           application.DB
	Auth                         login.KeycloakOAuthService
	LinkService                  link.LinkOAuthService
	TokenManager                 token.Manager
	Configuration                LoginConfiguration
	keycloakExternalTokenService keycloak.KeycloakExternalTokenService
	providerConfigFactory        link.OauthProviderFactory
}

// NewTokenController creates a token controller.
func NewTokenController(service *goa.Service, db application.DB, auth *login.KeycloakOAuthProvider, linkService link.LinkOAuthService, providerConfigFactory link.OauthProviderFactory, tokenManager token.Manager, kclient keycloak.KeycloakExternalTokenService, configuration LoginConfiguration) *TokenController {
	return &TokenController{
		Controller:                   service.NewController("token"),
		Auth:                         auth,
		LinkService:                  linkService,
		TokenManager:                 tokenManager,
		Configuration:                configuration,
		keycloakExternalTokenService: kclient,
		providerConfigFactory:        providerConfigFactory,
		db: db,
	}
}

// Keys returns public keys which should be used to verify tokens
func (c *TokenController) Keys(ctx *app.KeysTokenContext) error {
	var publicKeys token.JsonKeys
	if ctx.Format != nil && *ctx.Format == "pem" {
		publicKeys = c.TokenManager.PemKeys()
	} else {
		publicKeys = c.TokenManager.JsonWebKeys()
	}

	return ctx.OK(&app.PublicKeys{Keys: publicKeys.Keys})
}

// Refresh obtains a new access token using the refresh token.
func (c *TokenController) Refresh(ctx *app.RefreshTokenContext) error {
	refreshToken := ctx.Payload.RefreshToken
	if refreshToken == nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("refresh_token", nil).Expected("not nil"))
	}

	client := &http.Client{Timeout: 10 * time.Second}
	endpoint, err := c.Configuration.GetKeycloakEndpointToken(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Unable to get Keycloak token endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get Keycloak token endpoint URL")))
	}
	res, err := client.PostForm(endpoint, url.Values{
		"client_id":     {c.Configuration.GetKeycloakClientID()},
		"client_secret": {c.Configuration.GetKeycloakSecret()},
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

	t, err := token.ReadTokenSet(ctx, res)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	return ctx.OK(convertToken(*t))
}

func convertToken(t token.TokenSet) *app.AuthToken {
	return &app.AuthToken{Token: &app.TokenData{
		AccessToken:      t.AccessToken,
		ExpiresIn:        t.ExpiresIn,
		NotBeforePolicy:  t.NotBeforePolicy,
		RefreshExpiresIn: t.RefreshExpiresIn,
		RefreshToken:     t.RefreshToken,
		TokenType:        t.TokenType,
	}}
}

// Generate obtain the access token from Keycloak for the test user
func (c *TokenController) Generate(ctx *app.GenerateTokenContext) error {
	var tokens app.AuthTokenCollection

	tokenEndpoint, err := c.Configuration.GetKeycloakEndpointToken(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to get Keycloak token endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get Keycloak token endpoint URL")))
	}

	testuser, err := GenerateUserToken(ctx, tokenEndpoint, c.Configuration, c.Configuration.GetKeycloakTestUserName(), c.Configuration.GetKeycloakTestUserSecret())
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to get Generate User token")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to generate test token ")))
	}
	_, _, err = c.Auth.CreateOrUpdateIdentity(ctx, *testuser.Token.AccessToken)
	tokens = append(tokens, testuser)

	testuser, err = GenerateUserToken(ctx, tokenEndpoint, c.Configuration, c.Configuration.GetKeycloakTestUser2Name(), c.Configuration.GetKeycloakTestUser2Secret())
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to generate test token")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to generate test token")))
	}
	// Creates the testuser2 user and identity if they don't yet exist
	_, _, err = c.Auth.CreateOrUpdateIdentity(ctx, *testuser.Token.AccessToken)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to persist user properly")
	}
	tokens = append(tokens, testuser)

	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	return ctx.OK(tokens)
}

func (c *TokenController) getKeycloakExternalTokenURL(providerName string) string {
	// not moving this to config because this is temporary.
	return fmt.Sprintf("%s/auth/realms/%s/broker/%s/token", c.Configuration.GetKeycloakURL(), c.Configuration.GetKeycloakRealm(), providerName)
}

// Retrieve fetches the stored external provider token.
func (c *TokenController) Retrieve(ctx *app.RetrieveTokenContext) error {

	currentIdentity, err := login.ContextIdentity(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	tokenString := goajwt.ContextJWT(ctx).Raw

	if ctx.For == "" {
		return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("for", "").Expected("git or OpenShift resource URL"))
	}

	providerConfig, err := c.providerConfigFactory.NewOauthProvider(ctx, ctx.RequestData, ctx.For)
	if err != nil {

		return jsonapi.JSONErrorResponse(ctx, err)
	}
	providerName := providerConfig.TypeName()

	keycloakTokenResponse, err := c.keycloakExternalTokenService.Get(ctx, tokenString, c.getKeycloakExternalTokenURL(providerName))
	if err != nil {
		if reflect.TypeOf(err) == reflect.TypeOf(errors.UnauthorizedError{}) {
			externalToken, err := c.retrieveToken(ctx, providerConfig, *currentIdentity)
			if err != nil {
				return jsonapi.JSONErrorResponse(ctx, err)
			}
			if externalToken != nil {
				appResponse := modelToAppExternalToken(*externalToken)
				return ctx.OK(&appResponse)
			}
			linkURL := rest.AbsoluteURL(ctx.RequestData, client.LinkTokenPath())
			errorResponse := fmt.Sprintf("LINK url=%s, description=\"%s token is missing. Link %s account\"", linkURL, providerName, providerName)
			ctx.ResponseData.Header().Set("WWW-Authenticate", errorResponse)
		}
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	err = c.createOrUpdateToken(ctx, *keycloakTokenResponse, providerConfig, *currentIdentity)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	appResponse := appExternalToken(*keycloakTokenResponse)
	return ctx.OK(&appResponse)
}

func (c *TokenController) createOrUpdateToken(ctx context.Context, keycloakTokenResponse keycloak.KeycloakExternalTokenResponse, providerConfig link.ProviderConfig, currentIdentity uuid.UUID) error {
	err := application.Transactional(c.db, func(appl application.Application) error {
		err := appl.Identities().CheckExists(ctx, currentIdentity.String())
		if err != nil {
			return errors.NewUnauthorizedError(err.Error())
		}
		tokens, err := appl.ExternalTokens().LoadByProviderIDAndIdentityID(ctx, providerConfig.ID(), currentIdentity)
		if err != nil {
			return err
		}
		if len(tokens) > 0 {
			// It was re-linking. Overwrite the existing link.
			externalToken := tokens[0]
			externalToken.Token = keycloakTokenResponse.AccessToken
			err = appl.ExternalTokens().Save(ctx, &externalToken)
			if err == nil {
				log.Info(ctx, map[string]interface{}{
					"provider_name":     providerConfig.TypeName(),
					"identity_id":       currentIdentity,
					"external_token_id": externalToken.ID,
				}, "an existing token found, token from keycloak saved.")
			}
			return err
		}
		externalToken := provider.ExternalToken{
			Token:      keycloakTokenResponse.AccessToken,
			IdentityID: currentIdentity,
			Scope:      providerConfig.Scopes(),
			ProviderID: providerConfig.ID(),
		}
		err = appl.ExternalTokens().Create(ctx, &externalToken)
		if err == nil {
			log.Info(ctx, map[string]interface{}{
				"provider_name":     providerConfig.TypeName(),
				"identity_id":       currentIdentity,
				"external_token_id": externalToken.ID,
			}, "no old token found. account linked & new token saved.")
		}
		return err
	})
	return err
}

func (c *TokenController) retrieveToken(ctx context.Context, providerConfig link.ProviderConfig, currentIdentity uuid.UUID) (*provider.ExternalToken, error) {

	var externalToken *provider.ExternalToken
	err := application.Transactional(c.db, func(appl application.Application) error {
		err := appl.Identities().CheckExists(ctx, currentIdentity.String())
		if err != nil {
			return errors.NewUnauthorizedError(err.Error())
		}
		tokens, err := appl.ExternalTokens().LoadByProviderIDAndIdentityID(ctx, providerConfig.ID(), currentIdentity)
		if err != nil {
			return err
		}
		if len(tokens) > 0 {
			externalToken = &tokens[0]
		}
		return nil
	})
	return externalToken, err
}

func modelToAppExternalToken(externalToken provider.ExternalToken) app.ExternalToken {
	return app.ExternalToken{
		Scope:       externalToken.Scope,
		AccessToken: externalToken.Token,
		TokenType:   "bearer", // We aren't saving the token_type in the database
	}
}

func appExternalToken(k keycloak.KeycloakExternalTokenResponse) app.ExternalToken {
	return app.ExternalToken{
		Scope:       k.Scope,
		AccessToken: k.AccessToken,
		TokenType:   k.TokenType,
	}
}

// GenerateUserToken obtains the access token from Keycloak for the user
func GenerateUserToken(ctx context.Context, tokenEndpoint string, configuration LoginConfiguration, username string, userSecret string) (*app.AuthToken, error) {
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
	t, err := token.ReadTokenSet(ctx, res)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"token_endpoint": res,
			"err":            err,
		}, "Error when unmarshal json with access token")
		return nil, errors.NewInternalError(ctx, errs.Wrap(err, "error when unmarshal json with access token"))
	}

	return convertToken(*t), nil
}

// Link links the user account to an external resource provider such as GitHub
func (c *TokenController) Link(ctx *app.LinkTokenContext) error {
	tokenClaims, err := c.TokenManager.ParseToken(ctx, ctx.Payload.Token)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":   err,
			"token": ctx.Payload.Token,
		}, "unable to parse token")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError(err.Error()))
	}
	identityID := tokenClaims.StandardClaims.Subject

	var redirectURL string
	if ctx.Payload.Redirect == nil {
		redirectURL = ctx.RequestData.Header.Get("Referer")
		if redirectURL == "" {
			return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("redirect", "empty").Expected("redirect param or Referer header should be specified"))
		}
	} else {
		redirectURL = *ctx.Payload.Redirect
	}

	if !c.Configuration.IsOpenShiftLinkingEnabled() && strings.HasPrefix(ctx.Payload.For, c.Configuration.GetOpenShiftClientApiUrl()) {
		// OSO account linking is disabled by default in Dev Mode.
		ctx.ResponseData.Header().Set("Location", redirectURL)
		return ctx.SeeOther()
	}

	redirectLocation, err := c.LinkService.ProviderLocation(ctx, ctx.RequestData, identityID, ctx.Payload.For, redirectURL)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	ctx.ResponseData.Header().Set("Location", redirectLocation)
	return ctx.SeeOther()
}

// Callback is called by an external oauth2 resource provider such as GitHub as part of user's account linking flow
func (c *TokenController) Callback(ctx *app.CallbackTokenContext) error {
	redirectLocation, err := c.LinkService.Callback(ctx, ctx.RequestData, ctx.State, ctx.Code)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	ctx.ResponseData.Header().Set("Location", redirectLocation)
	return ctx.TemporaryRedirect()
}
