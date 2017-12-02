package controller

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"

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

	identity, _, err := c.Auth.CreateOrUpdateIdentity(ctx, *testuser.Token.AccessToken, c.Configuration)
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
	identity, _, err = c.Auth.CreateOrUpdateIdentity(ctx, *testuser.Token.AccessToken, c.Configuration)
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

	osConfig, ok := providerConfig.(*link.OpenShiftIdentityProvider)
	if ok && token.IsSpecificServiceAccount(ctx, []string{"fabric8-oso-proxy", "fabric8-tenant"}) {
		// This is a request from OSO proxy or tenant service to obtain a cluster wide token
		clusterToken := app.ExternalToken{
			Scope:       "<unknown>",
			AccessToken: osConfig.Cluster.ServiceAccountToken,
			TokenType:   "bearer",
		}
		log.Info(ctx, map[string]interface{}{
			"cluster": osConfig.Cluster.Name,
		}, "Returning a cluster wide token")
		return ctx.OK(&clusterToken)
	}

	externalToken, err := c.retrieveToken(ctx, providerConfig, *currentIdentity)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	if externalToken != nil {
		updatedToken, err := c.updateProfileIfEmpty(ctx, providerConfig, externalToken)
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, err)
		}
		appResponse := modelToAppExternalToken(updatedToken)
		return ctx.OK(&appResponse)
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
			"for":           ctx.For,
			"provider_name": providerName,
		}, "Unable to obtain external token from Keycloak. Account linking may be required.")

		linkURL := rest.AbsoluteURL(ctx.RequestData, client.LinkTokenPath())
		errorResponse := fmt.Sprintf("LINK url=%s, description=\"%s token is missing. Link %s account\"", linkURL, providerName, providerName)
		ctx.ResponseData.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate")
		ctx.ResponseData.Header().Set("WWW-Authenticate", errorResponse)
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("token is missing"))
	}

	externalToken, err = c.saveKeycloakToken(ctx, *keycloakTokenResponse, providerConfig, *currentIdentity)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	updatedToken, err := c.updateProfileIfEmpty(ctx, providerConfig, externalToken)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	appResponse := modelToAppExternalToken(updatedToken)

	return ctx.OK(&appResponse)
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
	providerConfig, err := c.providerConfigFactory.NewOauthProvider(ctx, ctx.RequestData, ctx.For)
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

// Exchange provides OAuth2 token exchange. Currently only grant_type="client_credentials" is supported
// allowing clients to authenticate using a service account ID and secret value.
// A service account token is returned as the result of successful exchange.
// May be expanded in the future to support other exchange types.
func (c *TokenController) Exchange(ctx *app.ExchangeTokenContext) error {
	payload := ctx.Payload
	if payload == nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("payload", "nil").Expected("not empty payload"))
	}
	if payload.ClientID == nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("client_id", "nil").Expected("Service Account ID"))
	}
	if payload.ClientSecret == nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("client_secret", "nil").Expected("Service Account secret"))
	}

	sa, found := c.Configuration.GetServiceAccounts()[*payload.ClientID]
	if !found {
		log.Error(ctx, map[string]interface{}{
			"client_id":     *payload.ClientID,
			"client_secret": *payload.ClientSecret,
		}, "Unknown Service Account ID")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("invalid Service Account ID or secret"))
	}
	secret := []byte(*payload.ClientSecret)
	for _, hash := range sa.Secrets {
		if bcrypt.CompareHashAndPassword([]byte(hash), secret) == nil {
			tokenType := "bearer"
			accessToken, err := c.TokenManager.GenerateServiceAccountToken(ctx.RequestData, sa.ID, sa.Name)
			if err != nil {
				return jsonapi.JSONErrorResponse(ctx, err)
			}
			pat := &app.OauthToken{
				AccessToken: &accessToken,
				TokenType:   &tokenType,
			}
			return ctx.OK(pat)
		}
	}
	log.Error(ctx, map[string]interface{}{
		"client_id":     *payload.ClientID,
		"client_secret": *payload.ClientSecret,
	}, "Service Account secret doesn't match")
	return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("invalid Service Account ID or secret"))
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
func (c *TokenController) updateProfileIfEmpty(ctx context.Context, providerConfig link.ProviderConfig, token *provider.ExternalToken) (provider.ExternalToken, error) {
	externalToken := *token
	if externalToken.Username == "" {
		userProfile, err := providerConfig.Profile(ctx, oauth2.Token{AccessToken: token.Token})
		if err != nil {
			return externalToken, err
		}
		externalToken.Username = userProfile.Username
	}
	err := application.Transactional(c.db, func(appl application.Application) error {
		return appl.ExternalTokens().Save(ctx, &externalToken)
	})
	return externalToken, err
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
		Username:    &externalToken.Username,
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
