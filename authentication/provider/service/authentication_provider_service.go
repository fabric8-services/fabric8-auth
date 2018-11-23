package service

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	name "github.com/fabric8-services/fabric8-auth/authentication/account"
	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/authentication/provider"
	providerrepo "github.com/fabric8-services/fabric8-auth/authentication/provider/repository"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	autherrors "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"golang.org/x/oauth2"
)

type AuthenticationProviderServiceConfig interface {
	provider.IdentityProviderConfiguration
	manager.TokenManagerConfiguration
	GetPublicOAuthClientID() string
	GetWITURL() (string, error)
}

type authenticationProviderServiceImpl struct {
	base.BaseService
	config AuthenticationProviderServiceConfig
}

const (
	apiClientParam = "api_client"
	apiTokenParam  = "api_token"
	tokenJSONParam = "token_json"
)

// NewAuthenticationProviderService returns a new AuthenticationProviderService implementation
func NewAuthenticationProviderService(ctx servicecontext.ServiceContext, config AuthenticationProviderServiceConfig) service.AuthenticationProviderService {
	return &authenticationProviderServiceImpl{
		BaseService: base.NewBaseService(ctx),
		config:      config,
	}
}

// GenerateAuthCodeURL is used by both the login and authorize endpoints to generate a URL to which the client will be
// redirected in order to obtain an authorization code, which will subsequently be exchanged for an access token.
// https://oauth.net/2/grant-types/authorization-code/
func (s *authenticationProviderServiceImpl) GenerateAuthCodeURL(ctx context.Context, redirect *string, apiClient *string,
	state *string, scopes []string, responseMode *string, referrer string, callbackURL string) (*string, error) {
	/* Compute all the configuration urls */
	validRedirectURL := s.config.GetValidRedirectURLs()

	// First time access, redirect to oauth provider
	if redirect == nil {
		if referrer == "" {
			return nil, autherrors.NewBadParameterError(
				"Referer Header and redirect param are both empty. At least one should be specified",
				redirect).Expected("redirect")
		}
		redirect = &referrer
	}

	// store referrer in a state reference to redirect later
	log.Debug(ctx, map[string]interface{}{
		"referrer": referrer,
		"redirect": redirect,
	}, "Got Request from!")

	redirect, err := s.saveParams(ctx, *redirect, apiClient)
	if err != nil {
		return nil, err
	}

	err = s.SaveReferrer(ctx, *state, *redirect, responseMode, validRedirectURL)
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

	// Create a new identity provider / configuration
	provider := s.Factories().IdentityProviderFactory().NewIdentityProvider(ctx, s.config)

	// Override the redirect URL, setting it to the callback URL that was passed in
	provider.SetRedirectURL(callbackURL)

	// Override the scopes if a value is passed in
	if scopes != nil {
		provider.SetScopes(scopes)
	}

	// Generate the Authorization Code URL
	redirectTo := provider.AuthCodeURL(*state, oauth2.AccessTypeOnline)

	return &redirectTo, err
}

// LoginCallback is invoked after the client has visited the authentication provider and state and code values are returned.
// These two parameters will be exchanged with the authentication provider for an access token, which will then be
// returned to the client.
func (s *authenticationProviderServiceImpl) LoginCallback(ctx context.Context, state string, code string, redirectURL string) (*string, error) {

	// After redirect from oauth provider
	log.Debug(ctx, map[string]interface{}{
		"code":  code,
		"state": state,
	}, "Redirected from oauth provider")

	referrerURL, _, err := s.reclaimReferrerAndResponseMode(ctx, state, code)
	if err != nil {
		return nil, err
	}

	providerToken, err := s.ExchangeCodeWithProvider(ctx, code, redirectURL)
	if err != nil {
		redirect := referrerURL.String() + "?error=" + err.Error()
		return &redirect, err
	}

	redirectTo, _, err := s.CreateOrUpdateIdentityAndUser(ctx, referrerURL, providerToken)
	if err != nil {
		return nil, err
	}

	if redirectTo != nil {
		return redirectTo, nil
	}

	redirect := referrerURL.String()
	return &redirect, nil
}

// AuthorizeCallback takes care of authorization callback.
// When authorization_code is requested with /api/authorize, oauth provider returns authorization_code at /api/authorize/callback,
// which would pass on the code along with the state to client using this method
func (s *authenticationProviderServiceImpl) AuthorizeCallback(ctx context.Context, state string, code string) (*string, error) {
	referrerURL, responseMode, err := s.reclaimReferrerAndResponseMode(ctx, state, code)
	if err != nil {
		return nil, err
	}

	redirectTo := buildRedirectURL(code, state, referrerURL, responseMode)
	return &redirectTo, nil
}

func buildRedirectURL(code string, state string, referrerURL *url.URL, responseMode *string) string {
	var parameters url.Values

	if responseMode != nil && *responseMode == "fragment" {
		parameters = url.Values{}
		parameters.Add("code", code)
		parameters.Add("state", state)
		if referrerURL.Fragment != "" {
			referrerURL.Fragment = referrerURL.Fragment + "&" + parameters.Encode()
		} else {
			referrerURL.Fragment = parameters.Encode()
		}
	} else {
		parameters = referrerURL.Query()
		parameters.Add("code", code)
		parameters.Add("state", state)
		referrerURL.RawQuery = parameters.Encode()
	}
	return referrerURL.String()
}

// ExchangeAuthorizationCodeForUserToken
func (s *authenticationProviderServiceImpl) ExchangeAuthorizationCodeForUserToken(ctx context.Context, code string, clientID string, redirectURL *url.URL) (*string, *app.OauthToken, error) {
	// Default value of this public client id is set to "740650a2-9c44-4db5-b067-a3d1b2cd2d01"
	if clientID != s.config.GetPublicOAuthClientID() {
		log.Error(ctx, map[string]interface{}{
			"client_id": clientID,
		}, "unknown oauth client id")
		return nil, nil, autherrors.NewUnauthorizedError("invalid oauth client id")
	}

	// Exchange the authorization code for an access token with the identity provider
	accessToken, err := s.ExchangeCodeWithProvider(ctx, code, redirectURL.String())
	if err != nil {
		return nil, nil, err
	}

	notApprovedRedirectURL, userToken, err := s.CreateOrUpdateIdentityAndUser(ctx, redirectURL, accessToken)
	if err != nil {
		return nil, nil, err
	}

	var token *app.OauthToken

	if userToken != nil {
		// Convert expiry to expire_in
		expiry := userToken.Expiry
		var expireIn *string
		if expiry != *new(time.Time) {
			exp := expiry.Sub(time.Now())
			if exp > 0 {
				seconds := strconv.FormatInt(int64(exp/time.Second), 10)
				expireIn = &seconds
			}
		}

		token = &app.OauthToken{
			AccessToken:  &userToken.AccessToken,
			ExpiresIn:    expireIn,
			RefreshToken: &userToken.RefreshToken,
			TokenType:    &userToken.TokenType,
		}
	}

	return notApprovedRedirectURL, token, nil
}

// Exchange exchanges the given code for OAuth2 token with the Authentication provider
func (s *authenticationProviderServiceImpl) ExchangeCodeWithProvider(ctx context.Context, code string, redirectURL string) (*oauth2.Token, error) {

	// Exchange the code for an access token
	provider := s.Factories().IdentityProviderFactory().NewIdentityProvider(ctx, s.config)
	provider.SetRedirectURL(redirectURL)
	token, err := provider.Exchange(ctx, code)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"code": code,
			"err":  err,
		}, "oauth exchange operation failed")
		return nil, autherrors.NewUnauthorizedError(err.Error())
	}

	log.Debug(ctx, map[string]interface{}{
		"code": code,
	}, "exchanged code to access token")

	return token, nil
}

// CreateOrUpdateIdentityAndUser creates or updates user and identity, checks whether the user is approved,
// encodes the token and returns final URL to which we are supposed to redirect
func (s *authenticationProviderServiceImpl) CreateOrUpdateIdentityAndUser(ctx context.Context, referrerURL *url.URL,
	token *oauth2.Token) (*string, *oauth2.Token, error) {

	tokenManager, err := manager.ReadTokenManagerFromContext(ctx)
	if err != nil {
		log.Error(nil, map[string]interface{}{
			"err": err,
		}, "failed to retrieve token manager from context")
		return nil, nil, autherrors.NewInternalError(ctx, err)
	}

	apiClient := referrerURL.Query().Get(apiClientParam)
	identity, err := s.UpdateIdentityUsingUserInfoEndPoint(ctx, token.AccessToken)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "failed to create a user and keycloak identity ")
		switch err.(type) {
		case autherrors.UnauthorizedError:
			if apiClient != "" {
				// Return the api token
				userToken, err := tokenManager.GenerateUserTokenForAPIClient(ctx, *token)
				if err != nil {
					log.Error(ctx, map[string]interface{}{"err": err}, "failed to generate token for API client")
					return nil, nil, err
				}
				err = encodeToken(ctx, referrerURL, userToken, apiClient)
				if err != nil {
					log.Error(ctx, map[string]interface{}{"err": err}, "failed to encode token")
					return nil, nil, err
				}
				log.Info(ctx, map[string]interface{}{
					"referrerURL": referrerURL.String(),
					"api_client":  apiClient,
				}, "return api token for unapproved user")
				redirectTo := referrerURL.String()
				return &redirectTo, userToken, nil
			}

			userNotApprovedRedirectURL := s.config.GetNotApprovedRedirect()
			if userNotApprovedRedirectURL != "" {
				status, err := s.Services().OSOSubscriptionService().LoadOSOSubscriptionStatus(ctx, *token)
				if err != nil {
					// Not critical. Just log the error and proceed
					log.Error(ctx, map[string]interface{}{"err": err}, "failed to load OSO subscription status")
				}
				userNotApprovedRedirectURL, err := rest.AddParam(userNotApprovedRedirectURL, "status", status)
				if err != nil {
					log.Error(ctx, map[string]interface{}{"err": err}, "failed to add a status param to the redirect URL")
					return nil, nil, err
				}
				log.Debug(ctx, map[string]interface{}{
					"user_not_approved_redirect_url": userNotApprovedRedirectURL,
				}, "user not approved; redirecting to registration app")
				return &userNotApprovedRedirectURL, nil, nil
			}
			return nil, nil, autherrors.NewUnauthorizedError(err.Error())
		}
		return nil, nil, err
	}

	if identity.User.Deprovisioned {
		log.Warn(ctx, map[string]interface{}{
			"identity_id": identity.ID,
			"user_name":   identity.Username,
		}, "deprovisioned user tried to login")
		return nil, nil, autherrors.NewUnauthorizedError("unauthorized access")
	}

	log.Debug(ctx, map[string]interface{}{
		"referrerURL": referrerURL.String(),
		"user_name":   identity.Username,
	}, "local user created/updated")

	// Generate a new user token instead of using the original oauth provider token
	userToken, err := tokenManager.GenerateUserTokenForIdentity(ctx, *identity, false)
	if err != nil {
		log.Error(ctx, map[string]interface{}{"err": err, "identity_id": identity.ID.String()}, "failed to generate token for user")
		return nil, nil, err
	}

	err = encodeToken(ctx, referrerURL, userToken, apiClient)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "failed to encode token")
		redirectTo := referrerURL.String() + err.Error()
		return &redirectTo, nil, autherrors.NewInternalError(ctx, err)
	}
	log.Debug(ctx, map[string]interface{}{
		"referrerURL": referrerURL.String(),
		"user_name":   identity.Username,
	}, "token encoded")

	redirectTo := referrerURL.String()
	return &redirectTo, userToken, nil
}

// UpdateIdentityFromExistingIdentityInfo update identity if exists using profile information and returns updated identity.
func (s *authenticationProviderServiceImpl) UpdateIdentityUsingUserInfoEndPoint(ctx context.Context, accessToken string) (*account.Identity, error) {
	userProfile, err := s.Factories().IdentityProviderFactory().NewIdentityProvider(ctx, s.config).Profile(ctx, oauth2.Token{AccessToken: accessToken})

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"token": accessToken,
			"err":   err,
		}, "unable to get user profile")
		return nil, errors.New("unable to get user profile " + err.Error())
	}

	identity := &account.Identity{}

	identities, err := s.Repositories().Identities().Query(account.IdentityFilterByUsername(userProfile.Username), account.IdentityWithUser())
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to query for an identity by username")
		return nil, errs.Wrapf(err, "error during querying for an identity by ID")
	}

	if len(identities) == 0 {
		return nil, autherrors.NewUnauthorizedError(fmt.Sprintf("user '%s' is not approved", userProfile.Username))
	}
	identity = &identities[0]

	// we had done a
	// s.Repositories().Identities().Query(account.IdentityFilterByUsername(userProfile.Username), account.IdentityWithUser())
	// so, identity.user should have been populated.

	if identity.User.ID == uuid.Nil {
		log.Error(ctx, map[string]interface{}{
			"identity_id": identity.ID,
		}, "token identity is not linked to any user")
		return nil, errors.New("token identity is not linked to any user")
	}

	if !identity.RegistrationCompleted {
		fillUserFromUserInfo(*userProfile, identity)
		identity.RegistrationCompleted = true
		err = s.ExecuteInTransaction(func() error {
			// Using the old-fashioned service
			err := s.Repositories().Identities().Save(ctx, identity)
			if err != nil {
				return err
			}
			err = s.Repositories().Users().Save(ctx, &identity.User)
			if err != nil {
				return err
			}
			return nil
		})
	}
	return identity, err
}

func (s *authenticationProviderServiceImpl) saveParams(ctx context.Context, redirect string, apiClient *string) (*string, error) {
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

// SaveReferrer validates referrer and saves it in DB
func (s *authenticationProviderServiceImpl) SaveReferrer(ctx context.Context, state string, referrer string,
	responseMode *string, validReferrerURL string) error {

	matched, err := regexp.MatchString(validReferrerURL, referrer)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"referrer":           referrer,
			"valid_referrer_url": validReferrerURL,
			"err":                err,
		}, "Can't match referrer and whitelist regex")
		return err
	}
	if !matched {
		log.Error(ctx, map[string]interface{}{
			"referrer":           referrer,
			"valid_referrer_url": validReferrerURL,
		}, "Referrer not valid")
		return autherrors.NewBadParameterError("redirect", "not valid redirect URL")
	}
	// TODO The state reference table will be collecting dead states left from some failed login attempts.
	// We need to clean up the old states from time to time.
	ref := providerrepo.OauthStateReference{
		State:        state,
		Referrer:     referrer,
		ResponseMode: responseMode,
	}

	err = s.ExecuteInTransaction(func() error {
		_, err := s.Repositories().OauthStates().Create(ctx, &ref)
		return err
	})

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"state":         state,
			"referrer":      referrer,
			"response_mode": log.PointerToString(responseMode),
			"err":           err,
		}, "unable to create oauth state reference")
		return err
	}
	return nil
}

// LoadReferrerAndResponseMode loads referrer and responseMode from DB
func (s *authenticationProviderServiceImpl) LoadReferrerAndResponseMode(ctx context.Context, state string) (string, *string, error) {
	var referrer string
	var responseMode *string

	err := s.ExecuteInTransaction(func() error {
		ref, err := s.Repositories().OauthStates().Load(ctx, state)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"state": state,
				"err":   err,
			}, "unable to load oauth state reference")
			return err
		}
		referrer = ref.Referrer
		responseMode = ref.ResponseMode
		err = s.Repositories().OauthStates().Delete(ctx, ref.ID)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"state": state,
				"err":   err,
			}, "unable to delete oauth state reference")
			return err
		}

		return nil
	})
	if err != nil {
		return "", nil, err
	}
	return referrer, responseMode, nil
}

// reclaimReferrer reclaims referrerURL and verifies the state
func (s *authenticationProviderServiceImpl) reclaimReferrerAndResponseMode(ctx context.Context, state string, code string) (*url.URL, *string, error) {
	knownReferrer, responseMode, err := s.LoadReferrerAndResponseMode(ctx, state)
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

// encodeToken
func encodeToken(ctx context.Context, referrer *url.URL, outhToken *oauth2.Token, apiClient string) error {
	tokenJSON, err := TokenToJSON(ctx, outhToken)

	if err != nil {
		return err
	}
	parameters := referrer.Query()
	if apiClient != "" {
		parameters.Add(apiTokenParam, tokenJSON)
	} else {
		parameters.Add(tokenJSONParam, tokenJSON)
	}
	referrer.RawQuery = parameters.Encode()
	return nil
}

// TokenToJSON marshals an oauth2 token to a json string
func TokenToJSON(ctx context.Context, outhToken *oauth2.Token) (string, error) {
	str := outhToken.Extra("expires_in")
	var expiresIn interface{}
	var refreshExpiresIn interface{}
	var err error
	expiresIn, err = manager.NumberToInt(str)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"expires_in": str,
			"err":        err,
		}, "unable to parse expires_in claim")
		return "", errs.WithStack(err)
	}
	str = outhToken.Extra("refresh_expires_in")
	refreshExpiresIn, err = manager.NumberToInt(str)
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

// fillUserFromUserInfo
func fillUserFromUserInfo(userinfo provider.UserProfile, identity *account.Identity) error {
	identity.User.FullName = name.GenerateFullName(&userinfo.GivenName, &userinfo.FamilyName)
	identity.User.Email = userinfo.Email
	identity.User.Company = userinfo.Company
	identity.Username = userinfo.Username
	if identity.User.ImageURL == "" {
		image, err := generateGravatarURL(userinfo.Email)
		if err != nil {
			log.Warn(nil, map[string]interface{}{
				"user_full_name": identity.User.FullName,
				"err":            err,
			}, "error when generating gravatar")
			// if there is an error, we will qualify the identity/user as unchanged.
			return errors.New("Error when generating gravatar " + err.Error())
		}
		identity.User.ImageURL = image
	}
	return nil
}

// generateGravatarURL
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
