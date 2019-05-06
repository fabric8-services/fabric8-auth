package controller

import (
	"context"
	"fmt"
	"net/url"
	"strconv"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/authentication/provider"
	"github.com/fabric8-services/fabric8-auth/authorization/token"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/client"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/goadesign/goa"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	"golang.org/x/crypto/bcrypt"
)

const (
	DevUsername = "developer"
	DevEmail    = "osio-developer@email.com"
)

type TokenControllerConfiguration interface {
	provider.IdentityProviderConfiguration
	IsPostgresDeveloperModeEnabled() bool
	GetServiceAccounts() map[string]configuration.ServiceAccount
	GetPublicOAuthClientID() string
}

// TokenController implements the login resource.
type TokenController struct {
	*goa.Controller
	app           application.Application
	TokenManager  manager.TokenManager
	Configuration TokenControllerConfiguration
}

// NewTokenController creates a token controller.
func NewTokenController(service *goa.Service, app application.Application, tokenManager manager.TokenManager,
	configuration TokenControllerConfiguration) *TokenController {
	return &TokenController{
		Controller:    service.NewController("token"),
		TokenManager:  tokenManager,
		Configuration: configuration,
		app:           app,
	}
}

// Keys returns public keys which should be used to verify tokens
func (c *TokenController) Keys(ctx *app.KeysTokenContext) error {
	var publicKeys token.JSONKeys
	if ctx.Format != nil && *ctx.Format == "pem" {
		publicKeys = c.TokenManager.PemKeys()
	} else {
		publicKeys = c.TokenManager.JSONWebKeys()
	}

	return ctx.OK(&app.PublicKeys{Keys: publicKeys.Keys})
}

// Refresh obtains a new access token using the refresh token.
func (c *TokenController) Refresh(ctx *app.RefreshTokenContext) error {
	// retrieve the access token if it exists (otherwise, a jwtrequest.ErrNoTokenInRequest is returned, but it can be ignored here)
	accessToken := goajwt.ContextJWT(ctx)
	refreshToken := ctx.Payload.RefreshToken
	if refreshToken == nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("refresh_token", nil).Expected("not nil"))
	}
	var t *manager.TokenSet
	var err error
	if accessToken != nil {
		t, err = c.app.TokenService().ExchangeRefreshToken(ctx, *refreshToken, accessToken.Raw)
	} else {
		t, err = c.app.TokenService().ExchangeRefreshToken(ctx, *refreshToken, "")
	}
	if err != nil {
		c.TokenManager.AddLoginRequiredHeaderToUnauthorizedError(err, ctx.ResponseData)
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	return ctx.OK(convertToken(*t))
}

func convertToken(t manager.TokenSet) *app.AuthToken {
	return &app.AuthToken{Token: &app.TokenData{
		AccessToken:      t.AccessToken,
		ExpiresIn:        t.ExpiresIn,
		NotBeforePolicy:  t.NotBeforePolicy,
		RefreshExpiresIn: t.RefreshExpiresIn,
		RefreshToken:     t.RefreshToken,
		TokenType:        t.TokenType,
	}}
}

// Retrieve fetches the stored external provider token.
func (c *TokenController) Retrieve(ctx *app.RetrieveTokenContext) error {
	appToken, errorResponse, err := c.app.TokenService().RetrieveExternalToken(ctx, ctx.For, ctx.RequestData, ctx.ForcePull)
	if errorResponse != nil {
		ctx.ResponseData.Header().Add("Access-Control-Expose-Headers", "WWW-Authenticate")
		ctx.ResponseData.Header().Set("WWW-Authenticate", *errorResponse)
	}
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "failed to retrieve token")
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	return ctx.OK(appToken)
}

// Status checks if the stored external provider token is available.
func (c *TokenController) Status(ctx *app.StatusTokenContext) error {
	appToken, errorResponse, err := c.app.TokenService().RetrieveExternalToken(ctx, ctx.For, ctx.RequestData, ctx.ForcePull)
	if errorResponse != nil {
		ctx.ResponseData.Header().Add("Access-Control-Expose-Headers", "WWW-Authenticate")
		ctx.ResponseData.Header().Set("WWW-Authenticate", *errorResponse)
	}
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "failed to check token status")
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	tokenStatus := &app.ExternalTokenStatus{
		Username:       appToken.Username,
		ProviderAPIURL: appToken.ProviderAPIURL,
	}
	return ctx.OK(tokenStatus)
}

// Delete deletes the stored external provider token.
func (c *TokenController) Delete(ctx *app.DeleteTokenContext) error {
	currentIdentity, err := manager.ContextIdentity(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	if ctx.For == "" {
		return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("for", "").Expected("git or OpenShift resource URL"))
	}

	err = c.app.TokenService().DeleteExternalToken(ctx, *currentIdentity, rest.AbsoluteURL(ctx.RequestData, "", nil), ctx.For)
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
	var notApprovedRedirect *string

	profileCtx := context.WithValue(ctx, provider.UserProfileContextKey, &provider.UserProfileContext{})

	switch payload.GrantType {
	case "client_credentials":
		token, err = c.exchangeWithGrantTypeClientCredentials(ctx)
	case "authorization_code":
		//notApprovedRedirect, token, err = c.exchangeWithGrantTypeAuthorizationCode(ctx)
		if payload.Code == nil {
			return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("code", "nil").Expected("authorization code"))
		}
		redirectURL, err := url.Parse(rest.AbsoluteURL(ctx.RequestData, client.CallbackAuthorizePath(), nil))
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"redirectURL": rest.AbsoluteURL(ctx.RequestData, client.CallbackAuthorizePath(), nil),
				"err":         err,
			}, "failed to parse referrer")
			return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
		}

		notApprovedRedirect, token, err = c.app.AuthenticationProviderService().ExchangeAuthorizationCodeForUserToken(
			profileCtx, *payload.Code, payload.ClientID, redirectURL)
		ctx.ResponseData.Header().Set("Cache-Control", "no-cache")

		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, err)
		}

	case "refresh_token":
		token, err = c.exchangeWithGrantTypeRefreshToken(ctx)
	default:
		return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("grant_type", payload.GrantType).Expected("grant_type=client_credentials or grant_type=authorization_code or grant_type=refresh_token"))
	}

	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	if notApprovedRedirect != nil && token == nil {
		// the code enters this block only if the user is not provisioned on OSO.
		userProfileContext, ok := profileCtx.Value(provider.UserProfileContextKey).(*provider.UserProfileContext)
		if ok {
			return jsonapi.JSONErrorResponse(ctx, errors.NewForbiddenError(
				fmt.Sprintf("user is not authorized to access OpenShift: %s", *userProfileContext.Username)))
		}
		return jsonapi.JSONErrorResponse(ctx, errors.NewForbiddenError("user is not authorized to access OpenShift"))
	}

	return ctx.OK(token)
}

func (c *TokenController) exchangeWithGrantTypeRefreshToken(ctx *app.ExchangeTokenContext) (*app.OauthToken, error) {
	// retrieve the RPT (passed as access token) from the request header, but ignore if it was not found
	accessToken := goajwt.ContextJWT(ctx)
	var rptToken string
	if accessToken != nil {
		rptToken = accessToken.Raw
	}
	payload := ctx.Payload
	refreshToken := payload.RefreshToken
	if refreshToken == nil {
		return nil, errors.NewBadParameterError("refresh_token", nil).Expected("not nil")
	}

	// Default value of this public client id is set to "740650a2-9c44-4db5-b067-a3d1b2cd2d01"
	if payload.ClientID != c.Configuration.GetPublicOAuthClientID() {
		log.Error(ctx, map[string]interface{}{
			"client_id": payload.ClientID,
		}, "unknown oauth client id")
		return nil, errors.NewUnauthorizedError("invalid oauth client id")
	}

	t, err := c.app.TokenService().ExchangeRefreshToken(ctx, *refreshToken, rptToken)
	if err != nil {
		c.TokenManager.AddLoginRequiredHeaderToUnauthorizedError(err, ctx.ResponseData)
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
			tokenType := "Bearer"
			accessToken, err := c.TokenManager.GenerateServiceAccountToken(sa.ID, sa.Name)
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

// Link links the user account to an external resource provider such as GitHub
func (c *TokenController) Link(ctx *app.LinkTokenContext) error {
	if ctx.For == "" {
		return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("for", "").Expected("git or OpenShift resource URL"))
	}
	currentIdentity, err := c.app.UserService().ContextIdentityIfExists(ctx)
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

	redirectLocation, err := c.app.LinkService().ProviderLocation(ctx, ctx.RequestData, currentIdentity.String(), ctx.For, redirectURL)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	locationPayload := &app.RedirectLocation{RedirectLocation: redirectLocation}
	return ctx.OK(locationPayload)
}

// LinkCallback is called by an external oauth2 resource provider such as GitHub as part of user's account linking flow
func (c *TokenController) LinkCallback(ctx *app.LinkCallbackTokenContext) error {
	redirectLocation, err := c.app.LinkService().Callback(ctx, ctx.RequestData, ctx.State, ctx.Code)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	ctx.ResponseData.Header().Set("Location", redirectLocation)
	return ctx.TemporaryRedirect()
}

func (c *TokenController) Audit(ctx *app.AuditTokenContext) error {
	token := goajwt.ContextJWT(ctx)
	if token == nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("no token in request"))
	}

	currentIdentity, err := c.app.UserService().LoadContextIdentityIfNotBanned(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	tokenString := token.Raw

	auditedToken, err := c.app.TokenService().Audit(ctx, currentIdentity, tokenString, ctx.ResourceID)
	if err != nil {
		switch t := err.(type) {
		case errors.UnauthorizedError:
			{
				if t.UnauthorizedCode == errors.UNAUTHORIZED_CODE_TOKEN_DEPROVISIONED {
					ctx.ResponseData.Header().Add("Access-Control-Expose-Headers", "WWW-Authenticate")
					ctx.ResponseData.Header().Set("WWW-Authenticate", "DEPROVISIONED description=\"Token has been banned\"")
					return jsonapi.JSONErrorResponse(ctx, err)
				} else if t.UnauthorizedCode == errors.UNAUTHORIZED_CODE_TOKEN_REVOKED {
					ctx.ResponseData.Header().Add("Access-Control-Expose-Headers", "WWW-Authenticate")
					ctx.ResponseData.Header().Set("WWW-Authenticate", "LOGIN description=\"Token has been revoked or logged out\"")
					return jsonapi.JSONErrorResponse(ctx, err)
				}
			}
		}

		return jsonapi.JSONErrorResponse(ctx, err)
	}

	if auditedToken != nil {
		rptToken := *auditedToken
		rptTokenPayload := &app.RPTToken{
			RptToken: &rptToken,
		}
		return ctx.OK(rptTokenPayload)
	}
	return ctx.OK(nil)
}
