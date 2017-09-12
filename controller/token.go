package controller

import (
	"context"
	"time"

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

const maxRecentSpacesForRPT = 10

// TokenController implements the login resource.
type TokenController struct {
	*goa.Controller
	Auth               login.KeycloakOAuthService
	TokenManager       token.Manager
	Configuration      LoginConfiguration
	identityRepository account.IdentityRepository
}

// NewTokenController creates a token controller.
func NewTokenController(service *goa.Service, auth *login.KeycloakOAuthProvider, tokenManager token.Manager, configuration LoginConfiguration, identityRepository account.IdentityRepository) *TokenController {
	return &TokenController{Controller: service.NewController("token"), Auth: auth, TokenManager: tokenManager, Configuration: configuration, identityRepository: identityRepository}
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

	token, err := auth.ReadToken(ctx, res)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	entitlementEndpoint, err := c.Configuration.GetKeycloakEndpointEntitlement(ctx.RequestData)
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
	if rpt != nil && int64(len(*rpt)) <= c.Configuration.GetHeaderMaxLength() {
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
	// Creates the testuser user and identity if they don't yet exist
	profileEndpoint, err := c.Configuration.GetKeycloakAccountEndpoint(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to get Keycloak account endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}
	WITEndpointUserProfile, err := c.Configuration.GetWITEndpoint(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to get Keycloak account endpoint URL")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}
	_, _, err = c.Auth.CreateOrUpdateKeycloakUser(*testuser.Token.AccessToken, ctx, profileEndpoint, WITEndpointUserProfile)
	tokens = append(tokens, testuser)

	testuser, err = GenerateUserToken(ctx, tokenEndpoint, c.Configuration, c.Configuration.GetKeycloakTestUser2Name(), c.Configuration.GetKeycloakTestUser2Secret())
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to generate test token")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to generate test token")))
	}
	// Creates the testuser2 user and identity if they don't yet exist
	_, _, err = c.Auth.CreateOrUpdateKeycloakUser(*testuser.Token.AccessToken, ctx, profileEndpoint, WITEndpointUserProfile)
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

// getEntitlementResourceRequestPayload creates the object which would have the information about which spaces/resources
// the entitlements' info would need to be fetched for.

func (c *TokenController) getEntitlementResourceRequestPayload(ctx context.Context, token *string) (*auth.EntitlementResource, error) {
	loggedInIdentityID, err := c.TokenManager.Extract(*token)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to get ID from access token")
		return nil, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get ID from access token"))
	}

	// get the user object as well for this identity
	queryResult, err := c.identityRepository.Query(account.IdentityFilterByID(loggedInIdentityID.ID), account.IdentityWithUser())
	if err != nil || len(queryResult) == 0 {
		log.Error(ctx, map[string]interface{}{
			"err":         err,
			"identity_id": *loggedInIdentityID,
		}, "unable to query Identity")
		return nil, errors.NewInternalError(ctx, errs.Wrap(err, "unable to query Identity"))
	}
	loggedInIdentity := queryResult[0]
	contextInfoLoggedInIdentity := loggedInIdentity.User.ContextInformation
	_, recentSpacesPresent := contextInfoLoggedInIdentity["recentSpaces"]
	if contextInfoLoggedInIdentity == nil || !recentSpacesPresent {
		log.Warn(ctx, map[string]interface{}{
			"identity_id": *loggedInIdentityID,
		}, "unable to find recentSpaces in ContextInformation")
		return nil, nil
	}

	var spacesToGetEntitlementsFor []auth.ResourceSet
	recentSpaces := contextInfoLoggedInIdentity["recentSpaces"].([]interface{})
	for i, v := range recentSpaces {
		if i == maxRecentSpacesForRPT {
			log.Info(ctx, map[string]interface{}{
				"identity_id":                   *loggedInIdentityID,
				"max_recent_spaces_for_rpt":     maxRecentSpacesForRPT,
				"total_number_of_recent_spaces": len(recentSpaces),
			}, "more than the allowed maximum number of recent spaces found")
			break
		}
		recentSpaceID, ok := v.(string)
		if !ok {
			log.Warn(ctx, map[string]interface{}{
				"identity_id": *loggedInIdentityID,
			}, "unable to find a string uuid in recentSpaces in contextInformation")
			return nil, nil
		}
		spacesToGetEntitlementsFor = append(spacesToGetEntitlementsFor, auth.ResourceSet{Name: recentSpaceID}) // pass by reference?
	}
	if len(spacesToGetEntitlementsFor) == 0 {
		log.Info(ctx, map[string]interface{}{
			"identity_id": *loggedInIdentityID,
		}, "no recent spaces found for optimizing fetching of rpt")
		return nil, nil
	}
	resource := &auth.EntitlementResource{
		Permissions: spacesToGetEntitlementsFor,
	}
	log.Info(ctx, map[string]interface{}{
		"identity_id": *loggedInIdentityID,
	}, "recent spaces will be used for fetching rpt")
	return resource, nil
}
