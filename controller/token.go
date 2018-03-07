package controller

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/client"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-auth/test"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/fabric8-services/fabric8-auth/token/keycloak"
	"github.com/fabric8-services/fabric8-auth/token/link"
	"github.com/fabric8-services/fabric8-auth/token/provider"
	"github.com/fabric8-services/fabric8-auth/wit"

	"github.com/goadesign/goa"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
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
func NewTokenController(service *goa.Service, db application.DB, auth login.KeycloakOAuthService, linkService link.LinkOAuthService, providerConfigFactory link.OauthProviderFactory, tokenManager token.Manager, kclient keycloak.KeycloakExternalTokenService, configuration LoginConfiguration) *TokenController {
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

	endpoint, err := c.Configuration.GetKeycloakEndpointToken(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Unable to get Keycloak token endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get Keycloak token endpoint URL")))
	}

	t, err := c.Auth.ExchangeRefreshToken(ctx, *refreshToken, endpoint, c.Configuration)
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

	identity, _, err := c.Auth.CreateOrUpdateIdentityInDB(ctx, *testuser.Token.AccessToken, c.Configuration)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to persist user properly")
	}
	tokens = append(tokens, testuser)

	var remoteWITService wit.RemoteWITServiceCaller
	witURL, err := c.Configuration.GetWITURL(ctx.RequestData)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	if identity != nil {
		err = remoteWITService.CreateWITUser(ctx, ctx.RequestData, identity, witURL, identity.ID.String())
		if err != nil {
			log.Warn(ctx, map[string]interface{}{
				"err":         err,
				"identity_id": identity.ID,
				"username":    identity.Username,
				"wit_url":     witURL,
			}, "unable to create user in WIT ")
		}
	}

	testuser, err = GenerateUserToken(ctx, tokenEndpoint, c.Configuration, c.Configuration.GetKeycloakTestUser2Name(), c.Configuration.GetKeycloakTestUser2Secret())
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to generate test token")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to generate test token")))
	}

	// Creates the testuser2 user and identity if they don't yet exist
	identity, _, err = c.Auth.CreateOrUpdateIdentityInDB(ctx, *testuser.Token.AccessToken, c.Configuration)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to persist user properly")
	}
	tokens = append(tokens, testuser)

	if identity != nil {
		err = remoteWITService.CreateWITUser(ctx, ctx.RequestData, identity, witURL, identity.ID.String())
		if err != nil {
			log.Warn(ctx, map[string]interface{}{
				"err":         err,
				"identity_id": identity.ID,
				"username":    identity.Username,
				"wit_url":     witURL,
			}, "unable to create user in WIT ")
		}
	}

	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	return ctx.OK(tokens)
}

func (c *TokenController) getKeycloakExternalTokenURL(providerName string) string {
	// not moving this to config because this is temporary.
	return fmt.Sprintf("%s/auth/realms/%s/broker/%s/token", c.Configuration.GetKeycloakURL(), c.Configuration.GetKeycloakRealm(), providerName)
}

func (c *TokenController) getKeycloakIdentityProviderURL(identityID string, providerName string) string {
	// not moving this to config because this is temporary.
	return fmt.Sprintf("%s/auth/admin/realms/%s/users/%s/federated-identity/%s", c.Configuration.GetKeycloakURL(), c.Configuration.GetKeycloakRealm(), identityID, providerName)
}

// Retrieve fetches the stored external provider token.
func (c *TokenController) Retrieve(ctx *app.RetrieveTokenContext) error {
	appToken, errorResponse, err := c.retrieveToken(ctx, ctx.For, ctx.RequestData, ctx.ForcePull)
	if errorResponse != nil {
		ctx.ResponseData.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate")
		ctx.ResponseData.Header().Set("WWW-Authenticate", *errorResponse)
	}
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	return ctx.OK(appToken)
}

// Status checks if the stored external provider token is available.
func (c *TokenController) Status(ctx *app.StatusTokenContext) error {
	appToken, errorResponse, err := c.retrieveToken(ctx, ctx.For, ctx.RequestData, ctx.ForcePull)
	if errorResponse != nil {
		ctx.ResponseData.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate")
		ctx.ResponseData.Header().Set("WWW-Authenticate", *errorResponse)
	}
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	tokenStatus := &app.ExternalTokenStatus{
		Username:       appToken.Username,
		ProviderAPIURL: appToken.ProviderAPIURL,
	}
	return ctx.OK(tokenStatus)
}

func (c *TokenController) retrieveToken(ctx context.Context, forResource string, req *goa.RequestData, forcePull *bool) (*app.ExternalToken, *string, error) {
	currentIdentity, err := login.ContextIdentity(ctx)
	if err != nil {
		return nil, nil, err
	}
	var appResponse app.ExternalToken

	tokenString := goajwt.ContextJWT(ctx).Raw

	if forResource == "" {
		return nil, nil, errors.NewBadParameterError("for", "").Expected("git or OpenShift resource URL")
	}

	providerConfig, err := c.providerConfigFactory.NewOauthProvider(ctx, *currentIdentity, req, forResource)
	if err != nil {
		return nil, nil, err
	}

	osConfig, ok := providerConfig.(link.OpenShiftIdentityProviderConfig)
	if ok && token.IsSpecificServiceAccount(ctx, token.OsoProxy, token.Tenant, token.JenkinsIdler, token.JenkinsProxy) {
		// This is a request from OSO proxy, tenant, Jenkins Idler, or Jenkins proxy service to obtain a cluster wide token
		return c.retrieveClusterToken(ctx, forResource, forcePull, osConfig)
	}

	externalToken, err := c.loadToken(ctx, providerConfig, *currentIdentity)
	if err != nil {
		return nil, nil, err
	}
	if externalToken != nil {
		updatedToken, errorResponse, err := c.updateProfileIfEmpty(ctx, forResource, req, providerConfig, externalToken, forcePull)
		if err != nil {
			return nil, errorResponse, err
		}
		appResponse = modelToAppExternalToken(updatedToken, providerConfig.URL())
		return &appResponse, nil, nil
	}

	providerName := providerConfig.TypeName()
	log.Info(ctx, map[string]interface{}{
		"provider_name": providerName,
		"identity_id":   currentIdentity,
	}, "External token not found. Will try to load from Keycloak.")
	keycloakTokenResponse, err := c.keycloakExternalTokenService.Get(ctx, tokenString, c.getKeycloakExternalTokenURL(providerName))
	if err != nil {
		log.Warn(ctx, map[string]interface{}{
			"err":           err,
			"for":           forResource,
			"provider_name": providerName,
		}, "Unable to obtain external token from Keycloak. Account linking may be required.")

		linkURL := rest.AbsoluteURL(req, fmt.Sprintf("%s?for=%s", client.LinkTokenPath(), forResource))
		errorResponse := fmt.Sprintf("LINK url=%s, description=\"%s token is missing. Link %s account\"", linkURL, providerName, providerName)
		return nil, &errorResponse, errors.NewUnauthorizedError("token is missing")
	}

	externalToken, err = c.saveKeycloakToken(ctx, *keycloakTokenResponse, providerConfig, *currentIdentity)
	if err != nil {
		return nil, nil, err
	}
	updatedToken, errorResponse, err := c.updateProfileIfEmpty(ctx, forResource, req, providerConfig, externalToken, forcePull)
	if err != nil {
		return nil, errorResponse, err
	}
	appResponse = modelToAppExternalToken(updatedToken, providerConfig.URL())

	return &appResponse, nil, nil
}

func (c *TokenController) retrieveClusterToken(ctx context.Context, forResource string, forcePull *bool, osConfig link.OpenShiftIdentityProviderConfig) (*app.ExternalToken, *string, error) {
	username := osConfig.OSOCluster().ServiceAccountUsername
	if forcePull != nil && *forcePull {
		userProfile, err := osConfig.Profile(ctx, oauth2.Token{AccessToken: osConfig.OSOCluster().ServiceAccountToken})
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"err": err,
				"for": forResource,
			}, "unable to fetch user profile for cluster token")
			errorResponse := fmt.Sprintf("LINK description=\"%s cluster token is not valid or expired", osConfig.OSOCluster().APIURL)
			return nil, &errorResponse, errors.NewUnauthorizedError(err.Error())
		}
		if osConfig.OSOCluster().ServiceAccountUsername != userProfile.Username {
			log.Warn(ctx, map[string]interface{}{
				"for": forResource,
				"configuration_username": osConfig.OSOCluster().ServiceAccountUsername,
				"user_profile_username":  userProfile.Username,
			}, "username from user profile for cluster token does not match username stored in configuration")
			username = userProfile.Username
		}
	}

	clusterToken := app.ExternalToken{
		Scope:          "<unknown>",
		AccessToken:    osConfig.OSOCluster().ServiceAccountToken,
		TokenType:      "bearer",
		Username:       username,
		ProviderAPIURL: osConfig.OSOCluster().APIURL,
	}
	log.Info(ctx, map[string]interface{}{
		"cluster": osConfig.OSOCluster().Name,
	}, "Returning a cluster wide token")
	return &clusterToken, nil, nil
}

// Delete deletes the stored external provider token.
func (c *TokenController) Delete(ctx *app.DeleteTokenContext) error {
	currentIdentity, err := login.ContextIdentity(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	if ctx.For == "" {
		return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("for", "").Expected("git or OpenShift resource URL"))
	}
	providerConfig, err := c.providerConfigFactory.NewOauthProvider(ctx, *currentIdentity, ctx.RequestData, ctx.For)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	// Delete from Keycloak
	err = c.keycloakExternalTokenService.Delete(ctx, c.getKeycloakIdentityProviderURL(currentIdentity.String(), providerConfig.TypeName()))
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"error":         err,
			"provider_name": providerConfig.TypeName(),
			"identity_id":   currentIdentity,
		}, "Unable to remove Identity Provider link from Keycloak.")
		// Not critical. Log the error and proceed.
	}

	// Delete from local DB
	err = application.Transactional(c.db, func(appl application.Application) error {
		err := appl.Identities().CheckExists(ctx, currentIdentity.String())
		if err != nil {
			return errors.NewUnauthorizedError(err.Error())
		}
		tokens, err := appl.ExternalTokens().LoadByProviderIDAndIdentityID(ctx, providerConfig.ID(), *currentIdentity)
		if err != nil {
			return err
		}
		if len(tokens) > 0 {
			for _, token := range tokens {
				err = appl.ExternalTokens().Delete(ctx, token.ID)
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	return ctx.OK([]byte{})
}

// Exchange provides OAuth2 and OpenID Connect token exchange.
// Currently only grant_type="client_credentials", "authorization_code", and "refresh_token" are supported.
//
// grant_type="client_credentials" allows clients to authenticate using a service account ID and secret value.
// A service account token is returned as the result of successful exchange.
//
// grant_type="authorization_code" is part of OAuth2 authorization flow.
//
// grant_type="refresh_token" covers OpenID Connect token refresh flow.
func (c *TokenController) Exchange(ctx *app.ExchangeTokenContext) error {
	payload := ctx.Payload
	if payload == nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("payload", "nil").Expected("not empty payload"))
	}

	log.Debug(ctx, map[string]interface{}{
		"client_id":  payload.ClientID,
		"grant_type": payload.GrantType,
	}, "token exchange")

	var err error
	var token *app.OauthToken

	switch payload.GrantType {
	case "client_credentials":
		token, err = c.exchangeWithGrantTypeClientCredentials(ctx)
	case "authorization_code":
		token, err = c.exchangeWithGrantTypeAuthorizationCode(ctx)
	case "refresh_token":
		token, err = c.exchangeWithGrantTypeRefreshToken(ctx)
	default:
		return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("grant_type", payload.GrantType).Expected("grant_type=client_credentials or grant_type=authorization_code or grant_type=refresh_token"))
	}

	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	return ctx.OK(token)
}

func (c *TokenController) exchangeWithGrantTypeRefreshToken(ctx *app.ExchangeTokenContext) (*app.OauthToken, error) {

	payload := ctx.Payload
	refreshToken := payload.RefreshToken
	if refreshToken == nil {
		return nil, errors.NewBadParameterError("refresh_token", nil).Expected("not nil")
	}

	// Default value of this public client id is set to "740650a2-9c44-4db5-b067-a3d1b2cd2d01"
	if payload.ClientID != c.Configuration.GetPublicOauthClientID() {
		log.Error(ctx, map[string]interface{}{
			"client_id": payload.ClientID,
		}, "unknown oauth client id")
		return nil, errors.NewUnauthorizedError("invalid oauth client id")
	}

	endpoint, err := c.Configuration.GetKeycloakEndpointToken(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Unable to get Keycloak token endpoint URL")
		return nil, errors.NewInternalErrorFromString(ctx, "unable to get Keycloak token endpoint URL")
	}

	t, err := c.Auth.ExchangeRefreshToken(ctx, *refreshToken, endpoint, c.Configuration)
	if err != nil {
		return nil, err
	}
	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")

	var expiresIn *string
	if t.ExpiresIn != nil {
		expIn := strconv.FormatInt(int64(*t.ExpiresIn), 10)
		expiresIn = &expIn
	}
	token := &app.OauthToken{
		AccessToken:  t.AccessToken,
		ExpiresIn:    expiresIn,
		RefreshToken: t.RefreshToken,
		TokenType:    t.TokenType,
	}

	return token, nil
}

func (c *TokenController) exchangeWithGrantTypeAuthorizationCode(ctx *app.ExchangeTokenContext) (*app.OauthToken, error) {
	payload := ctx.Payload
	if payload.Code == nil {
		return nil, errors.NewBadParameterError("code", "nil").Expected("authorization code")
	}
	// Default value of this public client id is set to "740650a2-9c44-4db5-b067-a3d1b2cd2d01"
	if payload.ClientID != c.Configuration.GetPublicOauthClientID() {
		log.Error(ctx, map[string]interface{}{
			"client_id": payload.ClientID,
		}, "unknown oauth client id")
		return nil, errors.NewUnauthorizedError("invalid oauth client id")
	}
	authEndpoint, err := c.Configuration.GetKeycloakEndpointAuth(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to get keycloak auth endpoint url")
		return nil, errors.NewInternalErrorFromString(ctx, "unable to get keycloak auth endpoint url")
	}

	tokenEndpoint, err := c.Configuration.GetKeycloakEndpointToken(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to get keycloak token endpoint url")
		return nil, errors.NewInternalErrorFromString(ctx, "unable to get keycloak token endpoint url")
	}

	oauth := &oauth2.Config{
		ClientID:     c.Configuration.GetKeycloakClientID(),
		ClientSecret: c.Configuration.GetKeycloakSecret(),
		Endpoint:     oauth2.Endpoint{AuthURL: authEndpoint, TokenURL: tokenEndpoint},
		RedirectURL:  rest.AbsoluteURL(ctx.RequestData, client.CallbackAuthorizePath()),
	}

	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")

	keycloakToken, err := c.Auth.Exchange(ctx, *payload.Code, oauth)

	if err != nil {
		return nil, err
	}

	redirectURL, err := url.Parse(oauth.RedirectURL)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"redirectURL": oauth.RedirectURL,
			"err":         err,
		}, "failed to parse referrer")
		return nil, errors.NewInternalError(ctx, err)
	}

	_, err = c.Auth.CreateOrUpdateIdentityAndUser(ctx, redirectURL, keycloakToken, ctx.RequestData, c.Configuration)

	if err != nil {
		return nil, err
	}

	// Convert expiry to expire_in
	expiry := keycloakToken.Expiry
	var expireIn *string
	if expiry != *new(time.Time) {
		exp := expiry.Sub(time.Now())
		if exp > 0 {
			seconds := strconv.FormatInt(int64(exp/time.Second), 10)
			expireIn = &seconds
		}
	}

	token := &app.OauthToken{
		AccessToken:  &keycloakToken.AccessToken,
		ExpiresIn:    expireIn,
		RefreshToken: &keycloakToken.RefreshToken,
		TokenType:    &keycloakToken.TokenType,
	}

	return token, nil
}

func (c *TokenController) exchangeWithGrantTypeClientCredentials(ctx *app.ExchangeTokenContext) (*app.OauthToken, error) {
	payload := ctx.Payload
	if payload.ClientSecret == nil {
		return nil, errors.NewBadParameterError("client_secret", "nil").Expected("Service Account secret")
	}

	sa, found := c.Configuration.GetServiceAccounts()[payload.ClientID]
	if !found {
		log.Error(ctx, map[string]interface{}{
			"client_id":     payload.ClientID,
			"client_secret": *payload.ClientSecret,
		}, "Unknown Service Account ID")
		return nil, errors.NewUnauthorizedError("invalid Service Account ID or secret")
	}
	secret := []byte(*payload.ClientSecret)
	for _, hash := range sa.Secrets {
		if bcrypt.CompareHashAndPassword([]byte(hash), secret) == nil {
			tokenType := "bearer"
			accessToken, err := c.TokenManager.GenerateServiceAccountToken(ctx.RequestData, sa.ID, sa.Name)
			if err != nil {
				return nil, err
			}
			pat := &app.OauthToken{
				AccessToken: &accessToken,
				TokenType:   &tokenType,
			}
			return pat, nil
		}
	}
	log.Error(ctx, map[string]interface{}{
		"client_id":     payload.ClientID,
		"client_secret": *payload.ClientSecret,
	}, "Service Account secret doesn't match")
	return nil, errors.NewUnauthorizedError("invalid Service Account ID or secret")
}

func (c *TokenController) saveKeycloakToken(ctx context.Context, keycloakTokenResponse keycloak.KeycloakExternalTokenResponse, providerConfig link.ProviderConfig, currentIdentity uuid.UUID) (*provider.ExternalToken, error) {
	var externalToken provider.ExternalToken
	err := application.Transactional(c.db, func(appl application.Application) error {
		externalToken = provider.ExternalToken{
			Token:      keycloakTokenResponse.AccessToken,
			IdentityID: currentIdentity,
			Scope:      providerConfig.Scopes(),
			ProviderID: providerConfig.ID(),
		}
		err := appl.ExternalTokens().Create(ctx, &externalToken)
		if err == nil {
			log.Info(ctx, map[string]interface{}{
				"provider_name":     providerConfig.TypeName(),
				"identity_id":       currentIdentity,
				"external_token_id": externalToken.ID,
			}, "no old token found. account linked & new token saved.")
		}
		return err
	})
	return &externalToken, err
}

// updateProfileIfEmpty checks if the username is missing in the token record (may happen to old accounts)
// loads the user profile from the identity provider and saves the username in the external token
func (c *TokenController) updateProfileIfEmpty(ctx context.Context, forResource string, req *goa.RequestData, providerConfig link.ProviderConfig, token *provider.ExternalToken, forcePull *bool) (provider.ExternalToken, *string, error) {
	externalToken := *token
	if externalToken.Username == "" || (forcePull != nil && *forcePull) {
		userProfile, err := providerConfig.Profile(ctx, oauth2.Token{AccessToken: token.Token})
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"err":           err,
				"for":           forResource,
				"provider_name": providerConfig.TypeName(),
			}, "Unable to fetch user profile for external token. Account relinking may be required.")
			linkURL := rest.AbsoluteURL(req, fmt.Sprintf("%s?for=%s", client.LinkTokenPath(), forResource))
			errorResponse := fmt.Sprintf("LINK url=%s, description=\"%s token is not valid or expired. Relink %s account\"", linkURL, providerConfig.TypeName(), providerConfig.TypeName())
			return externalToken, &errorResponse, errors.NewUnauthorizedError(err.Error())
		}
		externalToken.Username = userProfile.Username
		err = application.Transactional(c.db, func(appl application.Application) error {
			return appl.ExternalTokens().Save(ctx, &externalToken)
		})
		return externalToken, nil, err
	}
	return externalToken, nil, nil
}

func (c *TokenController) loadToken(ctx context.Context, providerConfig link.ProviderConfig, currentIdentity uuid.UUID) (*provider.ExternalToken, error) {
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

func modelToAppExternalToken(externalToken provider.ExternalToken, providerAPIURL string) app.ExternalToken {
	return app.ExternalToken{
		Scope:          externalToken.Scope,
		AccessToken:    externalToken.Token,
		TokenType:      "bearer", // We aren't saving the token_type in the database
		Username:       externalToken.Username,
		ProviderAPIURL: providerAPIURL,
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
	defer rest.CloseResponse(res)
	if res.StatusCode != http.StatusOK {
		bodyString := rest.ReadBody(res.Body)
		log.Error(ctx, map[string]interface{}{
			"response_status": res.Status,
			"response_body":   bodyString,
		}, "unable to obtain token")
		return nil, errors.NewInternalError(ctx, errs.Errorf("unable to obtain token. Response status: %s. Response body: %s", res.Status, bodyString))
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
	if ctx.For == "" {
		return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("for", "").Expected("git or OpenShift resource URL"))
	}
	currentIdentity, err := login.ContextIdentityIfExists(ctx, c.db)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	var redirectURL string
	if ctx.Redirect == nil {
		redirectURL = ctx.RequestData.Header.Get("Referer")
		if redirectURL == "" {
			return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("redirect", "empty").Expected("redirect param or Referer header should be specified"))
		}
	} else {
		redirectURL = *ctx.Redirect
	}

	redirectLocation, err := c.LinkService.ProviderLocation(ctx, ctx.RequestData, currentIdentity.String(), ctx.For, redirectURL)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	locationPayload := &app.RedirectLocation{RedirectLocation: redirectLocation}
	return ctx.OK(locationPayload)
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
