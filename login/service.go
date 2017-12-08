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

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	autherrors "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login/tokencontext"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-auth/token"
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
	GetValidRedirectURLs() string
	GetNotApprovedRedirect() string
	GetWITURL(*goa.RequestData) (string, error)
	GetOpenShiftClientApiUrl() string
}

// NewKeycloakOAuthProvider creates a new login.Service capable of using keycloak for authorization
func NewKeycloakOAuthProvider(identities account.IdentityRepository, users account.UserRepository, tokenManager token.Manager, db application.DB) *KeycloakOAuthProvider {
	return &KeycloakOAuthProvider{
		Identities:       identities,
		Users:            users,
		TokenManager:     tokenManager,
		db:               db,
		remoteWITService: &wit.RemoteWITServiceCaller{},
	}
}

// KeycloakOAuthProvider represents a keycloak IDP
type KeycloakOAuthProvider struct {
	Identities       account.IdentityRepository
	Users            account.UserRepository
	TokenManager     token.Manager
	db               application.DB
	remoteWITService wit.RemoteWITService
}

// KeycloakOAuthService represents keycloak OAuth service interface
type KeycloakOAuthService interface {
	Perform(ctx *app.LoginLoginContext, config oauth.OauthConfig, serviceConfig LoginServiceConfiguration) error
	PerformAuthorize(ctx *app.AuthorizeAuthorizeContext, config oauth.OauthConfig, serviceConfig LoginServiceConfiguration) error
	GetTokenFromAuthorizationCode(ctx context.Context, code string, config oauth.OauthConfig) (*oauth2.Token, error)
	VerifyState(ctx context.Context, state string, code string) (*url.URL, error)
	CreateOrUpdateIdentity(ctx context.Context, accessToken string, configuration LoginServiceConfiguration) (*account.Identity, bool, error)
	CreateOrUpdateIdentityAndUser(ctx context.Context, code string, referrerURL *url.URL, keycloakToken *oauth2.Token, request *goa.RequestData, config oauth.OauthConfig, serviceConfig LoginServiceConfiguration) (*string, error)
	BeforeRedirectToLogin(ctx context.Context, redirect *string, link *bool, apiClient *string, request *goa.RequestData, config oauth.OauthConfig, serviceConfig LoginServiceConfiguration) (*string, error)
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

// Perform performs authentication
func (keycloak *KeycloakOAuthProvider) Perform(ctx *app.LoginLoginContext, config oauth.OauthConfig, serviceConfig LoginServiceConfiguration) error {
	/* Compute all the configuration urls */
	//validRedirectURL := serviceConfig.GetValidRedirectURLs()

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

		referrerURL, err := keycloak.VerifyState(ctx, state, code)
		if err != nil {
			return err
		}

		keycloakToken, err := keycloak.GetTokenFromAuthorizationCode(ctx, code, config)

		if err != nil {
			return err
		}

		redirectTo, err := keycloak.CreateOrUpdateIdentityAndUser(ctx, code, referrerURL, keycloakToken, ctx.RequestData, config, serviceConfig)

		if redirectTo != nil {
			ctx.ResponseData.Header().Set("Location", *redirectTo)
			return ctx.TemporaryRedirect()
		}

		return err
	}

	// First time access, redirect to oauth provider

	redirectURL, err := keycloak.BeforeRedirectToLogin(ctx, ctx.Redirect, ctx.Link, ctx.APIClient, ctx.RequestData, config, serviceConfig)
	if err != nil {
		return err
	}
	ctx.ResponseData.Header().Set("Location", *redirectURL)
	return ctx.TemporaryRedirect()
}

// BeforeRedirectToLogin takes care of things parameter and state saving
func (keycloak *KeycloakOAuthProvider) BeforeRedirectToLogin(ctx context.Context, redirect *string, link *bool, apiClient *string, request *goa.RequestData, config oauth.OauthConfig, serviceConfig LoginServiceConfiguration) (*string, error) {
	/* Compute all the configuration urls */
	validRedirectURL := serviceConfig.GetValidRedirectURLs()

	// First time access, redirect to oauth provider
	referrer := request.Header.Get("Referer")
	if redirect == nil {
		if referrer == "" {
			return nil, jsonapi.JSONErrorResponse(ctx, autherrors.NewBadParameterError("Referer Header and redirect param are both empty. At least one should be specified", redirect).Expected("redirect"))
		}
		redirect = &referrer
	}

	// store referrer in a state reference to redirect later
	log.Debug(ctx, map[string]interface{}{
		"referrer": referrer,
		"redirect": redirect,
	}, "Got Request from!")

	stateID := uuid.NewV4()

	redirect, err := keycloak.saveParams(ctx, *redirect, link, apiClient)
	if err != nil {
		return nil, jsonapi.JSONErrorResponse(ctx, err)
	}

	err = keycloak.saveReferrer(ctx, stateID, *redirect, validRedirectURL)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"state":    stateID,
			"referrer": referrer,
			"redirect": redirect,
			"err":      err,
		}, "unable to save the state")
		return nil, err
	}

	redirectURL := config.AuthCodeURL(stateID.String(), oauth2.AccessTypeOnline)

	return &redirectURL, err
	/*ctx.ResponseData.Header().Set("Location", redirectURL)
	return ctx.TemporaryRedirect()*/
}

// GetTokenFromAuthorizationCode returns token and referralURL on recieving code and state
func (keycloak *KeycloakOAuthProvider) GetTokenFromAuthorizationCode(ctx context.Context, code string, config oauth.OauthConfig) (*oauth2.Token, error) {

	keycloakToken, err := config.Exchange(ctx, code)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"code": code,
			"err":  err,
		}, "keycloak exchange operation failed")
		return nil, jsonapi.JSONErrorResponse(ctx, autherrors.NewInternalError(ctx, err))
	}

	log.Debug(ctx, map[string]interface{}{
		"code": code,
	}, "exchanged code to access token")

	return keycloakToken, nil
}

// CreateOrUpdateIdentityAndUser creates or updates user and identity
func (keycloak *KeycloakOAuthProvider) CreateOrUpdateIdentityAndUser(ctx context.Context, code string, referrerURL *url.URL, keycloakToken *oauth2.Token, request *goa.RequestData, config oauth.OauthConfig, serviceConfig LoginServiceConfiguration) (*string, error) {

	brokerEndpoint, err := serviceConfig.GetKeycloakEndpointBroker(request)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Unable to get Keycloak broker endpoint URL")
		return nil, jsonapi.JSONErrorResponse(ctx, autherrors.NewInternalError(ctx, errs.Wrap(err, "unable to get Keycloak broker endpoint URL")))
	}

	witURL, err := serviceConfig.GetWITURL(request)
	if err != nil {
		return nil, jsonapi.JSONErrorResponse(ctx, autherrors.NewInternalError(ctx, err))
	}

	apiClient := referrerURL.Query().Get(apiClientParam)
	identity, newUser, err := keycloak.CreateOrUpdateIdentity(ctx, keycloakToken.AccessToken, serviceConfig)
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
					return nil, jsonapi.JSONErrorResponse(ctx, err)
				}
				log.Info(ctx, map[string]interface{}{
					"referrerURL": referrerURL.String(),
					"api_client":  apiClient,
				}, "return api token for unapproved user")
				redirectTo := referrerURL.String()
				return &redirectTo, nil
			}

			userNotApprovedRedirectURL := serviceConfig.GetNotApprovedRedirect()
			if userNotApprovedRedirectURL != "" {
				log.Debug(ctx, map[string]interface{}{
					"user_not_approved_redirect_url": userNotApprovedRedirectURL,
				}, "user not approved; redirecting to registration app")
				return &userNotApprovedRedirectURL, nil
			}
		}
		return nil, jsonapi.JSONErrorResponse(ctx, err)
	}

	log.Debug(ctx, map[string]interface{}{
		"code":        code,
		"referrerURL": referrerURL.String(),
		"user_name":   identity.Username,
	}, "local user created/updated")

	// new user for WIT
	if newUser {
		err = keycloak.remoteWITService.CreateWITUser(ctx, request, identity, witURL, identity.ID.String())
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
		return &redirectTo, jsonapi.JSONErrorResponse(ctx, autherrors.NewInternalError(ctx, err))
	}
	log.Debug(ctx, map[string]interface{}{
		"code":        code,
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

	// If the 'initlinking" param == true then initiate account linking if not already linked
	linked, err := keycloak.checkAllFederatedIdentities(ctx, keycloakToken.AccessToken, brokerEndpoint)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "failed to check federated identities")
		return nil, jsonapi.JSONErrorResponse(ctx, goa.ErrInternal(err.Error()))
	}
	log.Debug(ctx, map[string]interface{}{
		"code":        code,
		"referrerURL": referrerURL.String(),
		"user_name":   identity.Username,
		"linked":      linked,
	}, "identities links checked")

	// Return linked=true param if account has been linked to all IdPs or linked=false if not.
	if linked {
		referrerStr := referrerURL.String() + "&linked=true"
		redirectTo := referrerStr
		log.Info(ctx, map[string]interface{}{
			"referrerURL": referrerURL.String(),
			"user_name":   identity.Username,
			"linked":      linked,
			"api_client":  apiClient,
		}, "all good; redirecting back to referrer")
		return &redirectTo, nil
	}

	referrerStr := referrerURL.String() + "&linked=false"
	log.Debug(ctx, map[string]interface{}{
		"code":        code,
		"referrerURL": referrerURL.String(),
		"user_name":   identity.Username,
		"linked":      linked,
	}, "linking identities...")

	return keycloak.autoLinkProvidersDuringLogin(ctx, request, keycloakToken.AccessToken, referrerStr)

}

// PerformAuthorize takes care of authorize action
func (keycloak *KeycloakOAuthProvider) PerformAuthorize(ctx *app.AuthorizeAuthorizeContext, config oauth.OauthConfig, serviceConfig LoginServiceConfiguration) error {
	link := false
	redirectURL, err := keycloak.BeforeRedirectToLogin(ctx, &ctx.RedirectURI, &link, ctx.APIClient, ctx.RequestData, config, serviceConfig)
	if err != nil {
		return err
	}
	ctx.ResponseData.Header().Set("Location", *redirectURL)
	return ctx.TemporaryRedirect()
}

// VerifyState verifies the state and return referrerURL
func (keycloak *KeycloakOAuthProvider) VerifyState(ctx context.Context, state string, code string) (*url.URL, error) {
	knownReferrer, err := keycloak.getReferrer(ctx, state)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"state": state,
			"err":   err,
		}, "unknown state")
		return nil, jsonapi.JSONErrorResponse(ctx, autherrors.NewUnauthorizedError("unknown state: "+err.Error()))
	}
	referrerURL, err := url.Parse(knownReferrer)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"code":           code,
			"state":          state,
			"known_referrer": knownReferrer,
			"err":            err,
		}, "failed to parse referrer")
		return nil, jsonapi.JSONErrorResponse(ctx, autherrors.NewInternalError(ctx, err))
	}

	log.Debug(ctx, map[string]interface{}{
		"code":           code,
		"state":          state,
		"known_referrer": knownReferrer,
	}, "referrer found")

	return referrerURL, nil
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

func (keycloak *KeycloakOAuthProvider) saveParams(ctx context.Context, redirect string, link *bool, apiClient *string) (*string, error) {
	if apiClient != nil || (link != nil && *link) {
		// We need to save the "link" and "api_client" params so we don't lose them when redirect to sso for auth and back to auth.
		linkURL, err := url.Parse(redirect)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"redirect": redirect,
				"err":      err,
			}, "unable to parse redirect")
			return nil, autherrors.NewBadParameterError("redirect", redirect).Expected("valid URL")
		}
		parameters := linkURL.Query()
		if link != nil && *link {
			parameters.Add(initiateLinkingParam, strconv.FormatBool(*link))
		}
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

	state := uuid.NewV4()
	err := keycloak.saveReferrer(ctx, state, *rdr, validRedirectURL)
	if err != nil {
		return err
	}

	if provider != nil {
		return keycloak.linkProvider(ctx, req, res, state.String(), sessionState, *provider, nil, brokerEndpoint, clientID)
	}

	return keycloak.linkProvider(ctx, req, res, state.String(), sessionState, allProvidersToLink[0], &allProvidersToLink[1], brokerEndpoint, clientID)
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
	originalReferrer, err := keycloak.getReferrer(ctx, *state)
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

func (keycloak *KeycloakOAuthProvider) saveReferrer(ctx context.Context, state uuid.UUID, referrer string, validReferrerURL string) error {
	err := oauth.SaveReferrer(ctx, keycloak.db, state, referrer, validReferrerURL)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	return nil
}

func (keycloak *KeycloakOAuthProvider) getReferrer(ctx context.Context, state string) (string, error) {
	return oauth.LoadReferrer(ctx, keycloak.db, state)
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

// CreateOrUpdateIdentity creates a user and a keycloak identity. If the user and identity already exist then update them.
// Returns the user, identity and true if a new user and identity have been created
func (keycloak *KeycloakOAuthProvider) CreateOrUpdateIdentity(ctx context.Context, accessToken string, configuration LoginServiceConfiguration) (*account.Identity, bool, error) {

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

		err = application.Transactional(keycloak.db, func(appl application.Application) error {
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
		// let's update the existing user with the fullname, email and avatar from Keycloak,
		// in case the user changed them since the last time he/she logged in
		isChanged, err := fillUser(claims, identity)
		user := &identity.User
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"keycloak_identity_id": keycloakIdentityID,
				"err": err,
			}, "unable to create user/identity")
			return nil, false, errors.New("failed to update user/identity from claims" + err.Error())
		} else if isChanged {
			err = application.Transactional(keycloak.db, func(appl application.Application) error {
				err = appl.Users().Save(ctx, user)
				if err != nil {
					log.Error(ctx, map[string]interface{}{
						"user_id": user.ID,
						"err":     err,
					}, "unable to update user")
					return errors.New("failed to update user " + err.Error())
				}
				err = appl.Identities().Save(ctx, identity)
				if err != nil {
					log.Error(ctx, map[string]interface{}{
						"user_id": identity.ID,
						"err":     err,
					}, "unable to update identity")
					return errors.New("failed to update identity " + err.Error())
				}
				return err
			})
			if err != nil {
				log.Error(ctx, map[string]interface{}{
					"keycloak_identity_id": keycloakIdentityID,
					"username":             claims.Username,
					"err":                  err,
				}, "unable to update user/identity")
				return nil, false, errors.New("failed to update user/identity " + err.Error())
			}
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
	return keycloak.remoteWITService.UpdateWITUser(ctx, request, updateUserPayload, witURL, identityID)
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

// ContextIdentity returns the identity's ID found in given context if the identity exists in the Auth DB
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
