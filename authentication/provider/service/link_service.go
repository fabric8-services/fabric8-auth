package service

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/fabric8-services/fabric8-auth/rest"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	token "github.com/fabric8-services/fabric8-auth/authorization/token/repository"
	errs "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"golang.org/x/oauth2"
)

const (
	identityIDParam = "identity_id"
	forParam        = "for"
	nextParam       = "link_next"
)

// LinkServiceConfiguration the LinkService configuration
type LinkServiceConfiguration interface {
	GetValidRedirectURLs() string
}

// NewLinkService creates a new service for linking accounts
func NewLinkService(context servicecontext.ServiceContext, config LinkServiceConfiguration) service.LinkService {
	return &linkServiceImpl{
		BaseService: base.NewBaseService(context),
		config:      config,
	}
}

type linkServiceImpl struct {
	base.BaseService
	config LinkServiceConfiguration
}

// TODO remove goa parameters
// ProviderLocation returns a URL to OAuth 2.0 provider's consent page to be used to initiate account linking
func (s *linkServiceImpl) ProviderLocation(ctx context.Context, req *goa.RequestData, identityID string,
	forResource string, redirectURL string) (string, error) {
	// We need to save the "identityID" and "for" as params in the redirect location URL so we don't lose them when redirect to the provider for auth and back to auth.
	linkURL, err := url.Parse(redirectURL)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"redirect_url": redirectURL,
			"err":          err,
		}, "unable to parse redirectURL")
		return "", errs.NewBadParameterError("redirect", redirectURL).Expected("valid URL")
	}
	parameters := linkURL.Query()
	parameters.Set(identityIDParam, identityID)

	// If "for" contains multiple resources then do linking one by one
	forResources := strings.Split(forResource, ",")
	if len(forResources) > 1 {
		parameters.Set(nextParam, strings.Join(forResources[1:], ","))
	} else {
		parameters.Del(nextParam)
	}
	parameters.Set(forParam, forResources[0])
	linkURL.RawQuery = parameters.Encode()
	redirectURL = linkURL.String()

	identityUUID, err := uuid.FromString(identityID)
	if err != nil {
		return "", err
	}
	oauthProvider, err := s.Factories().LinkingProviderFactory().NewLinkingProvider(ctx, identityUUID,
		rest.AbsoluteURL(req, "", nil), forResources[0])
	if err != nil {
		return "", err
	}
	state := uuid.NewV4().String()
	err = s.Services().AuthenticationProviderService().SaveReferrer(ctx, state, redirectURL, nil, s.config.GetValidRedirectURLs())
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"redirect_url": redirectURL,
			"for":          forResource,
			"err":          err,
		}, "unable to save the state")
		return "", err
	}

	return oauthProvider.AuthCodeURL(state, oauth2.AccessTypeOnline), nil
}

// Callback returns a redirect URL after callback from an external oauth2 resource provider such as GitHub during user's account linking
func (s *linkServiceImpl) Callback(ctx context.Context, req *goa.RequestData, state string, code string) (string, error) {
	// validate known state
	knownReferrer, _, err := s.Services().AuthenticationProviderService().LoadReferrerAndResponseMode(ctx, state)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"state": state,
			"err":   err,
		}, "can't load referrer by state")
		return "", err
	}

	referrerURL, err := url.Parse(knownReferrer)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"code":           code,
			"state":          state,
			"known_referrer": knownReferrer,
			"err":            err,
		}, "failed to parse referrer")
		return "", err
	}

	identityID := referrerURL.Query().Get(identityIDParam)
	identityUUID, err := uuid.FromString(identityID)
	if err != nil {
		return "", err
	}

	forResource := referrerURL.Query().Get(forParam)

	oauthProvider, err := s.Factories().LinkingProviderFactory().NewLinkingProvider(ctx, identityUUID, rest.AbsoluteURL(req, "", nil), forResource)
	if err != nil {
		return "", err
	}

	providerToken, err := oauthProvider.Exchange(ctx, code)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"state": state,
			"code":  code,
			"err":   err,
		}, "exchange operation failed")
		return "", err
	}
	if providerToken.AccessToken == "" {
		log.Error(ctx, map[string]interface{}{
			"state":       state,
			"code":        code,
			"provider_id": oauthProvider.ID(),
		}, "access token return by provider is empty")
		return "", errors.New("access token return by provider is empty")
	}

	userProfile, err := oauthProvider.Profile(ctx, *providerToken)
	if err != nil {
		return "", err
	}
	err = s.ExecuteInTransaction(func() error {
		tokens, err := s.Repositories().ExternalTokens().LoadByProviderIDAndIdentityID(ctx, oauthProvider.ID(), identityUUID)
		if err != nil {
			return err
		}
		if len(tokens) > 0 {
			// It was re-linking. Overwrite the existing link.
			externalToken := tokens[0]
			externalToken.Token = providerToken.AccessToken
			externalToken.Username = userProfile.Username
			err = s.Repositories().ExternalTokens().Save(ctx, &externalToken)
			if err == nil {
				log.Info(ctx, map[string]interface{}{
					"provider_id":       oauthProvider.ID(),
					"identity_id":       identityID,
					"external_token_id": externalToken.ID,
				}, "An existing token found. Account re-linked & new token saved.")
			}
			return err
		}
		externalToken := token.ExternalToken{
			Token:      providerToken.AccessToken,
			IdentityID: identityUUID,
			Scope:      oauthProvider.Scopes(),
			ProviderID: oauthProvider.ID(),
			Username:   userProfile.Username,
		}
		err = s.Repositories().ExternalTokens().Create(ctx, &externalToken)
		if err == nil {
			log.Info(ctx, map[string]interface{}{
				"provider_id":       oauthProvider.ID(),
				"identity_id":       identityID,
				"external_token_id": externalToken.ID,
			}, "No old token found. Account linked & new token saved.")
		}
		return err
	})
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"state":       state,
			"code":        code,
			"provider_id": oauthProvider.ID(),
			"identity_id": identityID,
		}, "failed to save token")
		return "", err
	}

	nextResource := referrerURL.Query().Get(nextParam)
	if nextResource != "" {
		return s.ProviderLocation(ctx, req, identityID, nextResource, knownReferrer)
	}

	return knownReferrer, nil
}
