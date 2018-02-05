package login

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/auth"
	autherrors "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login/tokencontext"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-auth/token"
	keycloakTokenService "github.com/fabric8-services/fabric8-auth/token/keycloak"
	"github.com/fabric8-services/fabric8-auth/token/oauth"
	"github.com/fabric8-services/fabric8-auth/wit"

	"github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"golang.org/x/oauth2"
)

type LoginServiceConfiguration interface {
	GetKeycloakEndpointBroker(*goa.RequestData) (string, error)
	GetKeycloakEndpointToken(*goa.RequestData) (string, error)
	GetKeycloakClientID() string
	GetKeycloakSecret() string
	GetKeycloakEndpointUsers(*goa.RequestData) (string, error)
	GetValidRedirectURLs() string
	GetNotApprovedRedirect() string
	GetWITURL(*goa.RequestData) (string, error)
	GetOpenShiftClientApiUrl() string
	GetKeycloakAccountEndpoint(*goa.RequestData) (string, error)
}

// NewKeycloakOAuthProvider creates a new login.Service capable of using keycloak for authorization
func NewKeycloakOAuthProvider(identities account.IdentityRepository, users account.UserRepository, tokenManager token.Manager, db application.DB, keycloakProfileService UserProfileService) *KeycloakOAuthProvider {
	return &KeycloakOAuthProvider{
		Identities:             identities,
		Users:                  users,
		TokenManager:           tokenManager,
		DB:                     db,
		RemoteWITService:       &wit.RemoteWITServiceCaller{},
		keycloakProfileService: keycloakProfileService,
	}
}

// KeycloakOAuthProvider represents a keycloak IDP
type KeycloakOAuthProvider struct {
	Identities             account.IdentityRepository
	Users                  account.UserRepository
	TokenManager           token.Manager
	DB                     application.DB
	RemoteWITService       wit.RemoteWITService
	keycloakProfileService UserProfileService
}

// KeycloakOAuthService represents keycloak OAuth service interface
type KeycloakOAuthService interface {
	Login(ctx *app.LoginLoginContext, config oauth.OauthConfig, serviceConfig LoginServiceConfiguration) error
	AuthCodeURL(ctx context.Context, redirect *string, apiClient *string, state *string, responseMode *string, request *goa.RequestData, config oauth.OauthConfig, serviceConfig LoginServiceConfiguration) (*string, error)
	Exchange(ctx context.Context, code string, config oauth.OauthConfig) (*oauth2.Token, error)
	ExchangeRefreshToken(ctx context.Context, refreshToken string, endpoint string, serviceConfig LoginServiceConfiguration) (*token.TokenSet, error)
	AuthCodeCallback(ctx *app.CallbackAuthorizeContext) (*string, error)
	CreateOrUpdateIdentityInDB(ctx context.Context, accessToken string, configuration LoginServiceConfiguration) (*account.Identity, bool, error)
	CreateOrUpdateIdentityAndUser(ctx context.Context, referrerURL *url.URL, keycloakToken *oauth2.Token, request *goa.RequestData, serviceConfig LoginServiceConfiguration) (*string, error)
	Link(ctx *app.LinkLinkContext, brokerEndpoint string, clientID string, validRedirectURL string) error
	LinkSession(ctx *app.SessionLinkContext, brokerEndpoint string, clientID string, validRedirectURL string) error
	LinkCallback(ctx *app.CallbackLinkContext, brokerEndpoint string, clientID string) error
}

type linkInterface interface {
	context.Context
	jsonapi.InternalServerError
	TemporaryRedirect() error
	BadRequest(r *app.JSONAPIErrors) error
}

var allProvidersToLink = []string{"github", "openshift-v3"}

const (
	initiateLinkingParam = "initlinking"
	apiClientParam       = "api_client"
	apiTokenParam        = "api_token"
	tokenJSONParam       = "token_json"
)

// Login performs authentication
func (keycloak *KeycloakOAuthProvider) Login(ctx *app.LoginLoginContext, config oauth.OauthConfig, serviceConfig LoginServiceConfiguration) error {

	state := ctx.Params.Get("state")
	code := ctx.Params.Get("code")

	log.Debug(ctx, map[string]interface{}{
		"code":  code,
		"state": state,
	}, "login request received")

	if code != "" {
		// After redirect from oauth provider
		log.Debug(ctx, map[string]interface{}{
			"code":  code,
			"state": state,
		}, "Redirected from oauth provider")

		referrerURL, _, err := keycloak.reclaimReferrerAndResponseMode(ctx, state, code)
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, err)
		}

		keycloakToken, err := keycloak.Exchange(ctx, code, config)

		if err != nil {
			jsonapi.JSONErrorResponse(ctx, err)
			ctx.ResponseData.Header().Set("Location", referrerURL.String()+"?error="+err.Error())
			return ctx.TemporaryRedirect()
		}

		redirectTo, err := keycloak.CreateOrUpdateIdentityAndUser(ctx, referrerURL, keycloakToken, ctx.RequestData, serviceConfig)
		if err != nil {
			jsonapi.JSONErrorResponse(ctx, err)
		}

		if redirectTo != nil {
			ctx.ResponseData.Header().Set("Location", *redirectTo)
			return ctx.TemporaryRedirect()
		}

		ctx.ResponseData.Header().Set("Location", referrerURL.String()+"?error="+err.Error())
		return ctx.TemporaryRedirect()
	}

	// First time access, redirect to oauth provider
	generatedState := uuid.NewV4().String()
	redirectURL, err := keycloak.AuthCodeURL(ctx, ctx.Redirect, ctx.APIClient, &generatedState, nil, ctx.RequestData, config, serviceConfig)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	ctx.ResponseData.Header().Set("Location", *redirectURL)
	return ctx.TemporaryRedirect()
}

// AuthCodeURL is used in authorize action of /api/authorize to get authorization_code
func (keycloak *KeycloakOAuthProvider) AuthCodeURL(ctx context.Context, redirect *string, apiClient *string, state *string, responseMode *string, request *goa.RequestData, config oauth.OauthConfig, serviceConfig LoginServiceConfiguration) (*string, error) {
	/* Compute all the configuration urls */
	validRedirectURL := serviceConfig.GetValidRedirectURLs()

	// First time access, redirect to oauth provider
	referrer := request.Header.Get("Referer")
	if redirect == nil {
		if referrer == "" {
			return nil, autherrors.NewBadParameterError("Referer Header and redirect param are both empty. At least one should be specified", redirect).Expected("redirect")
		}
		redirect = &referrer
	}
	// store referrer in a state reference to redirect later
	log.Debug(ctx, map[string]interface{}{
		"referrer": referrer,
		"redirect": redirect,
	}, "Got Request from!")

	redirect, err := keycloak.saveParams(ctx, *redirect, apiClient)
	if err != nil {
		return nil, err
	}

	err = keycloak.saveReferrer(ctx, *state, *redirect, responseMode, validRedirectURL)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"state":         state,
			"referrer":      referrer,
			"redirect":      redirect,
			"response_mode": responseMode,
			"err":           err,
		}, "unable to save the state")
		return nil, err
	}

	redirectTo := config.AuthCodeURL(*state, oauth2.AccessTypeOnline)

	return &redirectTo, err
}

// Exchange returns token and referralURL on receiving code and state
func (keycloak *KeycloakOAuthProvider) Exchange(ctx context.Context, code string, config oauth.OauthConfig) (*oauth2.Token, error) {

	keycloakToken, err := config.Exchange(ctx, code)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"code": code,
			"err":  err,
		}, "keycloak exchange operation failed")
		return nil, autherrors.NewUnauthorizedError(err.Error())
	}

	log.Debug(ctx, map[string]interface{}{
		"code": code,
	}, "exchanged code to access token")

	return keycloakToken, nil
}

// ExchangeRefreshToken exchanges refreshToken for OauthToken
func (keycloak *KeycloakOAuthProvider) ExchangeRefreshToken(ctx context.Context, refreshToken string, endpoint string, serviceConfig LoginServiceConfiguration) (*token.TokenSet, error) {
	return keycloakTokenService.RefreshToken(ctx, endpoint, serviceConfig.GetKeycloakClientID(), serviceConfig.GetKeycloakSecret(), refreshToken)
}

// CreateOrUpdateIdentityAndUser creates or updates user and identity, checks whether the user is approved,
// encodes the token and returns final URL to which we are supposed to redirect
func (keycloak *KeycloakOAuthProvider) CreateOrUpdateIdentityAndUser(ctx context.Context, referrerURL *url.URL, keycloakToken *oauth2.Token, request *goa.RequestData, config LoginServiceConfiguration) (*string, error) {

	witURL, err := config.GetWITURL(request)
	if err != nil {
		return nil, autherrors.NewInternalError(ctx, err)
	}

	apiClient := referrerURL.Query().Get(apiClientParam)

	identity, newUser, err := keycloak.CreateOrUpdateIdentityInDB(ctx, keycloakToken.AccessToken, config)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "failed to create a user and keycloak identity ")
		switch err.(type) {
		case autherrors.UnauthorizedError:
			if apiClient != "" {
				// Return the api token
				err = encodeToken(ctx, referrerURL, keycloakToken, apiClient)
				if err != nil {
					log.Error(ctx, map[string]interface{}{
						"err": err,
					}, "failed to encode token")
					return nil, err
				}
				log.Info(ctx, map[string]interface{}{
					"referrerURL": referrerURL.String(),
					"api_client":  apiClient,
				}, "return api token for unapproved user")
				redirectTo := referrerURL.String()
				return &redirectTo, nil
			}

			userNotApprovedRedirectURL := config.GetNotApprovedRedirect()
			if userNotApprovedRedirectURL != "" {
				log.Debug(ctx, map[string]interface{}{
					"user_not_approved_redirect_url": userNotApprovedRedirectURL,
				}, "user not approved; redirecting to registration app")
				return &userNotApprovedRedirectURL, nil
			}
			return nil, autherrors.NewUnauthorizedError(err.Error())
		}
		return nil, err
	}

	log.Debug(ctx, map[string]interface{}{
		"referrerURL": referrerURL.String(),
		"user_name":   identity.Username,
	}, "local user created/updated")

	updatedKeycloakToken, err := keycloak.synchronizeAuthToKeycloak(ctx, request, keycloakToken, config, identity)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":         err,
			"identity_id": identity.ID,
			"username":    identity.Username,
		}, "unable to synchronize user from auth to keycloak ")

		// dont wish to cause a login error if something
		// goes wrong here
	} else if updatedKeycloakToken != nil {
		keycloakToken = updatedKeycloakToken
	}

	// new user for WIT
	if newUser {
		err = keycloak.RemoteWITService.CreateWITUser(ctx, request, identity, witURL, identity.ID.String())
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"err":         err,
				"identity_id": identity.ID,
				"username":    identity.Username,
				"wit_url":     witURL,
			}, "unable to create user in WIT ")
			// let's carry on instead of erroring out
		}
	} else {
		err = keycloak.updateWITUser(ctx, request, identity, witURL, identity.ID.String())
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"identity_id": identity.ID,
				"username":    identity.Username,
				"err":         err,
				"wit_url":     witURL,
			}, "unable to update user in WIT ")
			// let's carry on instead of erroring out
		}
	}

	err = encodeToken(ctx, referrerURL, keycloakToken, apiClient)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "failed to encode token")
		redirectTo := referrerURL.String() + err.Error()
		return &redirectTo, autherrors.NewInternalError(ctx, err)
	}
	log.Debug(ctx, map[string]interface{}{
		"referrerURL": referrerURL.String(),
		"user_name":   identity.Username,
	}, "token encoded")

	if s, err := strconv.ParseBool(referrerURL.Query().Get(initiateLinkingParam)); err != nil || !s {
		redirectTo := referrerURL.String()
		log.Info(ctx, map[string]interface{}{
			"referrerURL": referrerURL.String(),
			"user_name":   identity.Username,
			"api_client":  apiClient,
		}, "all good; redirecting back to referrer")
		return &redirectTo, nil
	}

	redirectTo := referrerURL.String()
	return &redirectTo, nil
}

func (keycloak *KeycloakOAuthProvider) updateUserInKeycloak(ctx context.Context, request *goa.RequestData, keycloakUser KeytcloakUserRequest, config LoginServiceConfiguration, identity *account.Identity) error {
	tokenEndpoint, err := config.GetKeycloakEndpointToken(request)
	if err != nil {
		return autherrors.NewInternalError(ctx, err)
	}
	protectedAccessToken, err := auth.GetProtectedAPIToken(ctx, tokenEndpoint, config.GetKeycloakClientID(), config.GetKeycloakSecret())
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"keycloak_client_id": config.GetKeycloakClientID(),
			"token_endpoint":     tokenEndpoint,
			"err":                err,
		}, "error generating PAT")
		return err
	}

	if protectedAccessToken != "" {
		// try hitting the admin user endpoint only if getting a PAT
		// was successful.

		usersEndpoint, err := config.GetKeycloakEndpointUsers(request)

		// not using userProfileService.Update() because it needs a user token
		// and here we don't have one.
		keycloakUserID, _, err := keycloak.keycloakProfileService.CreateOrUpdate(ctx, &keycloakUser, protectedAccessToken, usersEndpoint)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"err": err,
			}, "failed to update user in keycloak")
			return err
		} else {
			log.Info(ctx, map[string]interface{}{
				"keycloak_user_id": *keycloakUserID,
			}, "successfully updated user in keycloak")
			return nil
		}
	}
	return autherrors.NewInternalErrorFromString(ctx, "couldn't update profile because PAT wasn't generated")
}

func (keycloak *KeycloakOAuthProvider) synchronizeAuthToKeycloak(ctx context.Context, request *goa.RequestData, keycloakToken *oauth2.Token, config LoginServiceConfiguration, identity *account.Identity) (*oauth2.Token, error) {
	// Sync from auth db to keycloak.

	accountAPIEndpoint, err := config.GetKeycloakAccountEndpoint(request)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":       err,
			"user_name": identity.Username,
		}, "error getting account endpoint")
		return nil, err
	}

	claims, err := keycloak.TokenManager.ParseToken(ctx, keycloakToken.AccessToken)
	tokenRefreshNeeded := !keycloak.equalsTokenClaims(ctx, claims, *identity)
	log.Info(ctx, map[string]interface{}{
		"token_refresh_needed": tokenRefreshNeeded,
		"user_name":            identity.Username,
	}, "is token refresh needed ?")

	// if tokenRefreshNeeded = true, then we can deduce without GET-ing keycloak profile
	// that we need to (1) update keycloak user profile (2) refresh token.

	profileUpdateNeeded := tokenRefreshNeeded
	if !tokenRefreshNeeded {
		profileEqual, err := keycloak.equalsKeycloakUserProfileAttributes(ctx, keycloakToken.AccessToken, *identity, accountAPIEndpoint)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"err":       err,
				"user_name": identity.Username,
			}, "keycloak profile comparison failed")
			return nil, err
		}
		profileUpdateNeeded = !profileEqual
		log.Info(ctx, map[string]interface{}{
			"profile_updated_needed": profileUpdateNeeded,
			"user_name":              identity.Username,
		}, "is profile update needed ?")
	}

	profileUpdatePayload := keycloakUserRequestFromIdentity(*identity)
	if profileUpdateNeeded {
		err = keycloak.updateUserInKeycloak(ctx, request, profileUpdatePayload, config, identity)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"err":       err,
				"user_name": identity.Username,
			}, "keycloak profile update failed")
			return nil, err
		}
	}

	if tokenRefreshNeeded {
		endpoint, err := config.GetKeycloakEndpointToken(request)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"err":       err,
				"user_name": identity.Username,
			}, "error getting endpoint")
			return nil, err
		}

		tokenSet, err := keycloakTokenService.RefreshToken(ctx, endpoint, config.GetKeycloakClientID(), config.GetKeycloakSecret(), keycloakToken.AccessToken)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"err":               err,
				"keycloak_endpoint": endpoint,
				"user_name":         identity.Username,
			}, "refresh token failed")
			return nil, err
		}
		oauth2Token := &oauth2.Token{
			Expiry:       time.Unix(*tokenSet.ExpiresIn, 0),
			TokenType:    *tokenSet.TokenType,
			AccessToken:  *tokenSet.AccessToken,
			RefreshToken: *tokenSet.RefreshToken,
		}
		oauth2Token = oauth2Token.WithExtra(map[string]interface{}{
			"expires_in":         *tokenSet.ExpiresIn,
			"refresh_expires_in": *tokenSet.RefreshExpiresIn,
		})
		return oauth2Token, nil
	}

	return keycloakToken, err
}

// AuthCodeCallback takes care of authorization callback.
// When authorization_code is requested with /api/authorize, keycloak would return authorization_code at /api/authorize/callback,
// which would pass on the code along with the state to client using this method
func (keycloak *KeycloakOAuthProvider) AuthCodeCallback(ctx *app.CallbackAuthorizeContext) (*string, error) {
	referrerURL, responseMode, err := keycloak.reclaimReferrerAndResponseMode(ctx, ctx.State, ctx.Code)
	if err != nil {
		return nil, err
	}
	var redirectTo string
	parameters := referrerURL.Query()
	parameters.Add("code", ctx.Code)
	parameters.Add("state", ctx.State)

	if responseMode != nil && *responseMode == "fragment" {
		referrerURL.Fragment = parameters.Encode()
	} else {
		referrerURL.RawQuery = parameters.Encode()
	}
	redirectTo = referrerURL.String()

	return &redirectTo, nil
}

// reclaimReferrer reclaims referrerURL and verifies the state
func (keycloak *KeycloakOAuthProvider) reclaimReferrerAndResponseMode(ctx context.Context, state string, code string) (*url.URL, *string, error) {
	knownReferrer, responseMode, err := keycloak.getReferrerAndResponseMode(ctx, state)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"state": state,
			"err":   err,
		}, "unknown state")
		return nil, nil, autherrors.NewUnauthorizedError("unknown state: " + err.Error())
	}
	referrerURL, err := url.Parse(knownReferrer)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"code":           code,
			"state":          state,
			"known_referrer": knownReferrer,
			"err":            err,
		}, "failed to parse referrer")
		return nil, nil, autherrors.NewInternalError(ctx, err)
	}

	log.Debug(ctx, map[string]interface{}{
		"code":           code,
		"state":          state,
		"known_referrer": knownReferrer,
		"response_mode":  responseMode,
	}, "referrer found")

	return referrerURL, responseMode, nil
}

func encodeToken(ctx context.Context, referrer *url.URL, outhToken *oauth2.Token, apiClient string) error {
	tokenJson, err := TokenToJson(ctx, outhToken)
	if err != nil {
		return err
	}
	parameters := referrer.Query()
	if apiClient != "" {
		parameters.Add(apiTokenParam, tokenJson)
	} else {
		parameters.Add(tokenJSONParam, tokenJson)
	}
	referrer.RawQuery = parameters.Encode()
	return nil
}

func (keycloak *KeycloakOAuthProvider) saveParams(ctx context.Context, redirect string, apiClient *string) (*string, error) {
	if apiClient != nil {
		// We need to save"api_client" params so we don't lose them when redirect to sso for auth and back to auth.
		linkURL, err := url.Parse(redirect)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"redirect": redirect,
				"err":      err,
			}, "unable to parse redirect")
			return nil, autherrors.NewBadParameterError("redirect", redirect).Expected("valid URL")
		}
		parameters := linkURL.Query()
		if apiClient != nil {
			parameters.Add(apiClientParam, *apiClient)
		}
		linkURL.RawQuery = parameters.Encode()
		s := linkURL.String()
		return &s, nil
	}
	return &redirect, nil
}

func (keycloak *KeycloakOAuthProvider) autoLinkProvidersDuringLogin(ctx context.Context, request *goa.RequestData, token string, referrerURL string) (*string, error) {
	// Link all available Identity Providers
	linkURL, err := url.Parse(rest.AbsoluteURL(request, "/api/link/session"))
	if err != nil {
		return nil, jsonapi.JSONErrorResponse(ctx, goa.ErrInternal(err.Error()))
	}
	claims, err := keycloak.TokenManager.ParseToken(ctx, token)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to parse token")
		return nil, jsonapi.JSONErrorResponse(ctx, goa.ErrUnauthorized(err.Error()))
	}
	parameters := url.Values{}
	parameters.Add("redirect", referrerURL)
	parameters.Add("sessionState", fmt.Sprintf("%v", claims.SessionState))
	linkURL.RawQuery = parameters.Encode()
	redirectTo := linkURL.String()
	return &redirectTo, nil
}

// checkAllFederatedIdentities returns false if there is at least one federated identity not linked to the account
func (keycloak *KeycloakOAuthProvider) checkAllFederatedIdentities(ctx context.Context, token string, brokerEndpoint string) (bool, error) {
	for _, provider := range allProvidersToLink {
		linked, err := keycloak.checkFederatedIdentity(ctx, token, brokerEndpoint, provider)
		if err != nil {
			return false, err
		}
		if !linked {
			return false, nil
		}
	}
	return true, nil
}

// checkFederatedIdentity returns true if the account is already linked to the identity provider
func (keycloak *KeycloakOAuthProvider) checkFederatedIdentity(ctx context.Context, token string, brokerEndpoint string, provider string) (bool, error) {
	req, err := http.NewRequest("GET", brokerEndpoint+"/"+provider+"/token", nil)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err.Error(),
		}, "Unable to create http request")
		return false, autherrors.NewInternalError(ctx, errs.Wrap(err, "unable to create http request"))
	}
	req.Header.Add("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"provider": provider,
			"err":      err.Error(),
		}, "Unable to obtain a federated identity token")
		return false, autherrors.NewInternalError(ctx, errs.Wrap(err, "unable to obtain a federated identity token"))
	}
	defer rest.CloseResponse(res)
	return res.StatusCode == http.StatusOK, nil
}

// Link links identity provider(s) to the user's account using user's access token
func (keycloak *KeycloakOAuthProvider) Link(ctx *app.LinkLinkContext, brokerEndpoint string, clientID string, validRedirectURL string) error {
	token := goajwt.ContextJWT(ctx)
	claims := token.Claims.(jwt.MapClaims)
	sessionState := claims["session_state"]
	if sessionState == nil {
		return jsonapi.JSONErrorResponse(ctx, goa.ErrInternal("Session state is missing in token"))
	}
	ss := sessionState.(*string)
	return keycloak.linkAccountToProviders(ctx, ctx.RequestData, ctx.ResponseData, ctx.Redirect, ctx.Provider, *ss, brokerEndpoint, clientID, validRedirectURL)
}

// LinkSession links identity provider(s) to the user's account using session state
func (keycloak *KeycloakOAuthProvider) LinkSession(ctx *app.SessionLinkContext, brokerEndpoint string, clientID string, validRedirectURL string) error {
	if ctx.SessionState == nil {
		return jsonapi.JSONErrorResponse(ctx, goa.ErrBadRequest("Authorization header or session state param is required"))
	}
	return keycloak.linkAccountToProviders(ctx, ctx.RequestData, ctx.ResponseData, ctx.Redirect, ctx.Provider, *ctx.SessionState, brokerEndpoint, clientID, validRedirectURL)
}

func (keycloak *KeycloakOAuthProvider) linkAccountToProviders(ctx linkInterface, req *goa.RequestData, res *goa.ResponseData, redirect *string, provider *string, sessionState string, brokerEndpoint string, clientID string, validRedirectURL string) error {
	referrer := req.Header.Get("Referer")

	rdr := redirect
	if rdr == nil {
		rdr = &referrer
	}

	state := uuid.NewV4().String()
	err := keycloak.saveReferrer(ctx, state, *rdr, nil, validRedirectURL)
	if err != nil {
		return err
	}

	if provider != nil {
		return keycloak.linkProvider(ctx, req, res, state, sessionState, *provider, nil, brokerEndpoint, clientID)
	}

	return keycloak.linkProvider(ctx, req, res, state, sessionState, allProvidersToLink[0], &allProvidersToLink[1], brokerEndpoint, clientID)
}

// LinkCallback redirects to original referrer when Identity Provider account are linked to the user account
func (keycloak *KeycloakOAuthProvider) LinkCallback(ctx *app.CallbackLinkContext, brokerEndpoint string, clientID string) error {
	state := ctx.State
	errorMessage := ctx.Params.Get("error")
	if state == nil {
		jsonapi.JSONErrorResponse(ctx, goa.ErrInternal("State is empty. "+errorMessage))
	}
	if errorMessage != "" {
		return jsonapi.JSONErrorResponse(ctx, goa.ErrInternal(errorMessage))
	}

	next := ctx.Next
	if next != nil {
		// Link the next provider
		sessionState := ctx.SessionState
		if sessionState == nil {
			log.Error(ctx, map[string]interface{}{
				"state": state,
			}, "session state is empty")
			jerrors, _ := jsonapi.ErrorToJSONAPIErrors(ctx, goa.ErrBadRequest("session state is empty"))
			return ctx.Unauthorized(jerrors)
		}
		providerURL, err := getProviderURL(ctx.RequestData, *state, *sessionState, *next, nextProvider(*next), brokerEndpoint, clientID)
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, goa.ErrInternal(err.Error()))
		}
		ctx.ResponseData.Header().Set("Location", providerURL)
		return ctx.TemporaryRedirect()
	}

	// No more providers to link. Redirect back to the original referrer
	originalReferrer, _, err := keycloak.getReferrerAndResponseMode(ctx, *state)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"state": state,
			"err":   err,
		}, "uknown state")
		jerrors, _ := jsonapi.ErrorToJSONAPIErrors(ctx, goa.ErrUnauthorized("uknown state. "+err.Error()))
		return ctx.Unauthorized(jerrors)
	}

	ctx.ResponseData.Header().Set("Location", originalReferrer)
	return ctx.TemporaryRedirect()
}

func nextProvider(currentProvider string) *string {
	for i, provider := range allProvidersToLink {
		if provider == currentProvider {
			if i+1 < len(allProvidersToLink) {
				return &allProvidersToLink[i+1]
			}
			return nil
		}
	}
	return nil
}

func (keycloak *KeycloakOAuthProvider) linkProvider(ctx linkInterface, req *goa.RequestData, res *goa.ResponseData, state string, sessionState string, provider string, nextProvider *string, brokerEndpoint string, clientID string) error {
	providerURL, err := getProviderURL(req, state, sessionState, provider, nextProvider, brokerEndpoint, clientID)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, goa.ErrInternal(err.Error()))
	}
	res.Header().Set("Location", providerURL)
	return ctx.TemporaryRedirect()
}

func (keycloak *KeycloakOAuthProvider) saveReferrer(ctx context.Context, state string, referrer string, responseMode *string, validReferrerURL string) error {
	err := oauth.SaveReferrer(ctx, keycloak.DB, state, referrer, responseMode, validReferrerURL)
	if err != nil {
		return err
	}
	return nil
}

func (keycloak *KeycloakOAuthProvider) getReferrerAndResponseMode(ctx context.Context, state string) (string, *string, error) {
	return oauth.LoadReferrerAndResponseMode(ctx, keycloak.DB, state)
}

func getProviderURL(req *goa.RequestData, state string, sessionState string, provider string, nextProvider *string, brokerEndpoint string, clientID string) (string, error) {
	var nextParam string
	if nextProvider != nil {
		nextParam = "&next=" + *nextProvider
	}
	callbackURL := rest.AbsoluteURL(req, "/api/link/callback?provider="+provider+nextParam+"&sessionState="+sessionState+"&state="+state)

	nonce := uuid.NewV4().String()

	s := nonce + sessionState + clientID + provider
	h := sha256.New()
	h.Write([]byte(s))
	hash := base64.StdEncoding.EncodeToString(h.Sum(nil))

	linkingURL, err := url.Parse(brokerEndpoint + "/" + provider + "/link")
	if err != nil {
		return "", err
	}

	parameters := url.Values{}
	parameters.Add("provider_id", provider)
	parameters.Add("client_id", clientID)
	parameters.Add("redirect_uri", callbackURL)
	parameters.Add("nonce", nonce)
	parameters.Add("hash", hash)
	linkingURL.RawQuery = parameters.Encode()

	return linkingURL.String(), nil
}

// CreateOrUpdateIdentityInDB creates a user and a keycloak identity. If the user and identity already exist then update them.
// Returns the user, identity and true if a new user and identity have been created
func (keycloak *KeycloakOAuthProvider) CreateOrUpdateIdentityInDB(ctx context.Context, accessToken string, configuration LoginServiceConfiguration) (*account.Identity, bool, error) {

	newIdentityCreated := false
	claims, err := keycloak.TokenManager.ParseToken(ctx, accessToken)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"token": accessToken,
			"err":   err,
		}, "unable to parse the token")
		return nil, false, errors.New("unable to parse the token " + err.Error())
	}

	if err := token.CheckClaims(claims); err != nil {
		log.Error(ctx, map[string]interface{}{
			"token": accessToken,
			"err":   err,
		}, "invalid keycloak token claims")
		return nil, false, errors.New("invalid keycloak token claims " + err.Error())
	}

	if !claims.Approved {
		return nil, false, autherrors.NewUnauthorizedError(fmt.Sprintf("user '%s' is not approved", claims.Username))
	}

	keycloakIdentityID, _ := uuid.FromString(claims.Subject)

	identity := &account.Identity{}
	// TODO : Check this only if UUID is not null
	// If identity already existed in WIT, then IDs should match !
	if identity.Username != "" && keycloakIdentityID.String() != identity.ID.String() {
		log.Error(ctx, map[string]interface{}{
			"keycloak_identity_id": keycloakIdentityID,
			"wit_identity_id":      identity.ID,
			"err":                  err,
		}, "keycloak identity id and existing identity id in wit service does not match")
		return nil, false, errors.New("Keycloak identity ID and existing identity ID in WIT does not match")
	}

	identities, err := keycloak.Identities.Query(account.IdentityFilterByID(keycloakIdentityID), account.IdentityWithUser())
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"keycloak_identity_id": keycloakIdentityID,
			"err": err,
		}, "unable to  query for an identity by ID")
		return nil, false, errors.New("Error during querying for an identity by ID " + err.Error())
	}

	if len(identities) == 0 {
		// No Identity found, create a new Identity and User

		// Now that user/identity objects have been initialized, update it
		// from the token claims info.

		_, err = fillUser(claims, identity)
		if identity.User.Cluster == "" {
			identity.User.Cluster = configuration.GetOpenShiftClientApiUrl()
		}
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"keycloak_identity_id": keycloakIdentityID,
				"err": err,
			}, "unable to create user/identity")
			return nil, false, errors.New("failed to update user/identity from claims" + err.Error())
		}

		err = application.Transactional(keycloak.DB, func(appl application.Application) error {
			user := &identity.User
			err := appl.Users().Create(ctx, user)
			if err != nil {
				return err
			}

			identity.ID = keycloakIdentityID
			identity.ProviderType = account.KeycloakIDP
			identity.UserID = account.NullUUID{UUID: user.ID, Valid: true}
			identity.User = *user
			err = appl.Identities().Create(ctx, identity)
			return err
		})
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"keycloak_identity_id": keycloakIdentityID,
				"username":             claims.Username,
				"err":                  err,
			}, "unable to create user/identity")
			return nil, false, errors.New("failed to create user/identity " + err.Error())
		}
		newIdentityCreated = true
	} else {
		identity = &identities[0]

		// we had done a
		// keycloak.Identities.Query(account.IdentityFilterByID(keycloakIdentityID), account.IdentityWithUser())
		// so, identity.user should have been populated.

		if identity.User.ID == uuid.Nil {
			log.Error(ctx, map[string]interface{}{
				"identity_id": keycloakIdentityID,
			}, "Found Keycloak identity is not linked to any User")
			return nil, false, errors.New("found Keycloak identity is not linked to any User")
		}
	}
	return identity, newIdentityCreated, err
}

func (keycloak *KeycloakOAuthProvider) updateWITUser(ctx context.Context, request *goa.RequestData, identity *account.Identity, witURL string, identityID string) error {
	updateUserPayload := &app.UpdateUsersPayload{
		Data: &app.UpdateUserData{
			Attributes: &app.UpdateIdentityDataAttributes{
				Bio:      &identity.User.Bio,
				Company:  &identity.User.Company,
				Email:    &identity.User.Email,
				FullName: &identity.User.FullName,
				ImageURL: &identity.User.ImageURL,
				URL:      &identity.User.URL,
				Username: &identity.Username,
			},
		},
	}
	return keycloak.RemoteWITService.UpdateWITUser(ctx, request, updateUserPayload, witURL, identityID)
}

func generateGravatarURL(email string) (string, error) {
	if email == "" {
		return "", nil
	}
	grURL, err := url.Parse("https://www.gravatar.com/avatar/")
	if err != nil {
		return "", errs.WithStack(err)
	}
	hash := md5.New()
	hash.Write([]byte(email))
	grURL.Path += fmt.Sprintf("%v", hex.EncodeToString(hash.Sum(nil))) + ".jpg"

	// We can use our own default image if there is no gravatar available for this email
	// defaultImage := "someDefaultImageURL.jpg"
	// parameters := url.Values{}
	// parameters.Add("d", fmt.Sprintf("%v", defaultImage))
	// grURL.RawQuery = parameters.Encode()

	urlStr := grURL.String()
	return urlStr, nil
}

// equalsKeycloakUserProfile returns whether
// profile updated is needed & whether token refresh is needed.

func (keycloak *KeycloakOAuthProvider) equalsTokenClaims(ctx context.Context, claims *token.TokenClaims, identity account.Identity) bool {
	computedFullName := account.GenerateFullName(&claims.GivenName, &claims.FamilyName)
	if identity.Username != claims.Username ||
		identity.User.FullName != computedFullName ||
		identity.User.Company != claims.Company ||
		identity.User.Email != claims.Email ||
		identity.User.EmailVerified != claims.EmailVerified {
		log.Error(ctx, map[string]interface{}{
			"user":     identity.User,
			"claims":   claims,
			"fullName": computedFullName,
		}, "claims and local db data don't match")
		return false
	}
	return true
}

// equalsKeycloakUserProfileAttributes verifies the response from keycloak's user profile
// and returns true if it matches with the user information managed locally by the auth service.
func (keycloak *KeycloakOAuthProvider) equalsKeycloakUserProfileAttributes(ctx context.Context, accessToken string, identity account.Identity, userAPIEndpoint string) (bool, error) {
	profileEqual := true

	retrievedUserProfile, err := keycloak.keycloakProfileService.Get(ctx, accessToken, userAPIEndpoint)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"username": identity.Username,
			"err":      err,
		}, "error getting user's info from keycloak")

		return false, err
	}

	computedFullName := account.GenerateFullName(retrievedUserProfile.FirstName, retrievedUserProfile.LastName)

	if (retrievedUserProfile.Username == nil || identity.Username != *retrievedUserProfile.Username) ||
		(retrievedUserProfile.Email == nil || identity.User.Email != *retrievedUserProfile.Email) ||
		identity.User.FullName != computedFullName ||
		retrievedUserProfile.Attributes == nil ||
		(retrievedUserProfile.EmailVerified == nil || identity.User.EmailVerified != *retrievedUserProfile.EmailVerified) {
		profileEqual = false
	}
	keycloakAttributes := retrievedUserProfile.Attributes
	if keycloakAttributes == nil ||
		!equalsKeycloakAttribute(*keycloakAttributes, CompanyAttributeName, identity.User.Company) ||
		!equalsKeycloakAttribute(*keycloakAttributes, BioAttributeName, identity.User.Bio) ||
		!equalsKeycloakAttribute(*keycloakAttributes, ImageURLAttributeName, identity.User.ImageURL) ||
		!equalsKeycloakAttribute(*keycloakAttributes, ClusterAttribute, identity.User.Cluster) {

		profileEqual = false
	}

	log.Info(ctx, map[string]interface{}{
		"profile_equal": profileEqual,
	}, "is keycloak profile in sync with auth db ?")

	return profileEqual, nil
}

func fillUser(claims *token.TokenClaims, identity *account.Identity) (bool, error) {
	isChanged := false
	if identity.User.FullName != claims.Name || identity.User.Email != claims.Email || identity.User.Company != claims.Company || identity.Username != claims.Username || identity.User.ImageURL == "" {
		isChanged = true
	} else {
		return isChanged, nil
	}
	identity.User.FullName = claims.Name
	identity.User.Email = claims.Email
	identity.User.Company = claims.Company
	identity.User.EmailVerified = claims.EmailVerified
	identity.Username = claims.Username
	if identity.User.ImageURL == "" {
		image, err := generateGravatarURL(claims.Email)
		if err != nil {
			log.Warn(nil, map[string]interface{}{
				"user_full_name": identity.User.FullName,
				"err":            err,
			}, "error when generating gravatar")
			// if there is an error, we will qualify the identity/user as unchanged.
			return false, errors.New("Error when generating gravatar " + err.Error())
		}
		identity.User.ImageURL = image
	}
	return isChanged, nil
}

// ContextIdentity returns the identity's ID found in given context
// Uses tokenManager.Locate to fetch the identity of currently logged in user
func ContextIdentity(ctx context.Context) (*uuid.UUID, error) {
	tm := tokencontext.ReadTokenManagerFromContext(ctx)
	if tm == nil {
		log.Error(ctx, map[string]interface{}{
			"token": tm,
		}, "missing token manager")

		return nil, errs.New("Missing token manager")
	}
	// As mentioned in token.go, we can now safely convert tm to a token.Manager
	manager := tm.(token.Manager)
	uuid, err := manager.Locate(ctx)
	if err != nil {
		// TODO : need a way to define user as Guest
		log.Error(ctx, map[string]interface{}{
			"uuid":          uuid,
			"token_manager": manager,
			"err":           err,
		}, "identity belongs to a Guest User")

		return nil, errs.WithStack(err)
	}
	return &uuid, nil
}

// ContextIdentityIfExists returns the identity's ID found in given context if the identity exists in the Auth DB
// If it doesn't exist then an Unauthorized error is returned
func ContextIdentityIfExists(ctx context.Context, db application.DB) (uuid.UUID, error) {
	identity, err := ContextIdentity(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	// Check if the identity exists
	err = application.Transactional(db, func(appl application.Application) error {
		err := appl.Identities().CheckExists(ctx, identity.String())
		if err != nil {
			return autherrors.NewUnauthorizedError(err.Error())
		}
		return nil
	})
	if err != nil {
		return uuid.Nil, err
	}
	return *identity, nil
}

// InjectTokenManager is a middleware responsible for setting up tokenManager in the context for every request.
func InjectTokenManager(tokenManager token.Manager) goa.Middleware {
	return func(h goa.Handler) goa.Handler {
		return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
			ctxWithTM := tokencontext.ContextWithTokenManager(ctx, tokenManager)
			return h(ctxWithTM, rw, req)
		}
	}
}

// TokenToJson marshals an oauth2 token to a json string
func TokenToJson(ctx context.Context, outhToken *oauth2.Token) (string, error) {
	str := outhToken.Extra("expires_in")
	var expiresIn interface{}
	var refreshExpiresIn interface{}
	var err error
	expiresIn, err = token.NumberToInt(str)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"expires_in": str,
			"err":        err,
		}, "unable to parse expires_in claim")
		return "", errs.WithStack(err)
	}
	str = outhToken.Extra("refresh_expires_in")
	refreshExpiresIn, err = token.NumberToInt(str)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"refresh_expires_in": str,
			"err":                err,
		}, "unable to parse expires_in claim")
		return "", errs.WithStack(err)
	}
	tokenData := &app.TokenData{
		AccessToken:      &outhToken.AccessToken,
		RefreshToken:     &outhToken.RefreshToken,
		TokenType:        &outhToken.TokenType,
		ExpiresIn:        &expiresIn,
		RefreshExpiresIn: &refreshExpiresIn,
	}
	b, err := json.Marshal(tokenData)
	if err != nil {
		return "", errs.WithStack(err)
	}

	return string(b), nil
}
