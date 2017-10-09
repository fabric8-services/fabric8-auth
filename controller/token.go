package controller

import (
	"context"
	"time"

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
	"github.com/goadesign/goa"
	errs "github.com/pkg/errors"
)

const maxRecentSpacesForRPT = 10

// TokenController implements the login resource.
type TokenController struct {
	*goa.Controller
	Auth                            login.KeycloakOAuthService
	TokenManager                    token.Manager
	Configuration                   LoginConfiguration
	identityRepository              account.IdentityRepository
	externalProviderTokenRepository provider.ExternalProviderTokenRepository
}

// NewTokenController creates a token controller.
func NewTokenController(service *goa.Service, auth *login.KeycloakOAuthProvider, tokenManager token.Manager, configuration LoginConfiguration, identityRepository account.IdentityRepository, externalProviderTokenRepository provider.ExternalProviderTokenRepository) *TokenController {
	return &TokenController{Controller: service.NewController("token"), Auth: auth, TokenManager: tokenManager, Configuration: configuration, identityRepository: identityRepository, externalProviderTokenRepository: externalProviderTokenRepository}
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

// Retrieve fetches the stored external provider token.
func (c *TokenController) Retrieve(ctx *app.RetrieveTokenContext) error {

	currentIdentity, err := login.ContextIdentity(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, goa.ErrUnauthorized(err.Error()))
	}

	if ctx.For == "" {
		return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("for", "").Expected("github or openshift-v3 resource"))
	}
	externalProviderType, error := provider.GetExternalProvider(ctx.For)
	if error != nil {
		return jsonapi.JSONErrorResponse(ctx, error)
	}

	// no clue why I have this now - but definitely won't be using SCOPE to query at the moment.
	scope := ctx.Scope
	if scope == nil || *scope == "" {
		scope = &externalProviderType.DefaultScope
	}
	externalProviderTokens, err := c.externalProviderTokenRepository.LoadByProviderIDAndIdentityID(ctx, externalProviderType.ID, *currentIdentity)

	if len(externalProviderTokens) > 0 {
		// not sure if we'll need more than 1 tokens in future.

		//TODO: move transformation to a different method.

		ID := externalProviderTokens[0].ID.String()
		return ctx.OK(&app.ExternalProviderToken{
			Data: &app.ExternalProviderTokenData{
				Attributes: &app.ExternalProviderTokenDataAttributes{
					CreatedAt:            &externalProviderTokens[0].CreatedAt,
					ExternalProviderType: externalProviderType.Type,
					IdentityID:           currentIdentity.String(),
					Scope:                externalProviderTokens[0].Scope,
					UpdatedAt:            &externalProviderTokens[0].UpdatedAt,
					Token:                externalProviderTokens[0].Token,
				},
				Type: "external_provider_token",
				ID:   &ID,
			},
		})
	}

	// TODO: return the www-authenticate response header.
	return jsonapi.JSONErrorResponse(ctx, errors.NewNotFoundError("external_provider_token", ctx.For))

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
