package service

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/auth"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/token/oauth"
	"golang.org/x/oauth2"
	"net/url"
	"regexp"
)

type AuthenticationProviderConfiguration interface {
	GetValidRedirectURLs() string
}

type authenticationProviderServiceImpl struct {
	base.BaseService
	config AuthenticationProviderConfiguration
}

const (
	apiClientParam = "api_client"
	apiTokenParam  = "api_token"
	tokenJSONParam = "token_json"
)

func NewAuthenticationProviderService(context servicecontext.ServiceContext, conf AuthenticationProviderConfiguration) service.AuthenticationProviderService {
	return &authenticationProviderServiceImpl{
		BaseService: base.NewBaseService(context),
		config:      conf,
	}
}

// GenerateAuthCodeURL is used by both the login and authorize endpoints to generate a URL to which the client will be
// redirected in order to obtain an authorization code, which will subsequently be exchanged for an access token.
// https://oauth.net/2/grant-types/authorization-code/
func (s *authenticationProviderServiceImpl) GenerateAuthCodeURL(ctx context.Context, redirect *string, apiClient *string,
	state *string, responseMode *string, referrer string, config oauth.OauthConfig) (*string, error) {
	/* Compute all the configuration urls */
	validRedirectURL := s.config.GetValidRedirectURLs()

	// First time access, redirect to oauth provider
	if redirect == nil {
		if referrer == "" {
			return nil, errors.NewBadParameterError(
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

	err = s.saveReferrer(ctx, *state, *redirect, responseMode, validRedirectURL)
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

func (s *authenticationProviderServiceImpl) saveParams(ctx context.Context, redirect string, apiClient *string) (*string, error) {
	if apiClient != nil {
		// We need to save"api_client" params so we don't lose them when redirect to sso for auth and back to auth.
		linkURL, err := url.Parse(redirect)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"redirect": redirect,
				"err":      err,
			}, "unable to parse redirect")
			return nil, errors.NewBadParameterError("redirect", redirect).Expected("valid URL")
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
func (s *authenticationProviderServiceImpl) saveReferrer(ctx context.Context, state string, referrer string,
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
		return errors.NewBadParameterError("redirect", "not valid redirect URL")
	}
	// TODO The state reference table will be collecting dead states left from some failed login attempts.
	// We need to clean up the old states from time to time.
	ref := auth.OauthStateReference{
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
