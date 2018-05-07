package link

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/configuration"
	errs "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-auth/token/oauth"
	"github.com/fabric8-services/fabric8-auth/token/provider"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/application/transaction"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"golang.org/x/oauth2"
)

const (
	identityIDParam = "identity_id"
	forParam        = "for"
	nextParam       = "link_next"
)

// ProviderConfig represents OAuth2 config for linking accounts
type ProviderConfig interface {
	oauth.IdentityProvider
	ID() uuid.UUID
	Scopes() string
	TypeName() string
	URL() string
}

// LinkOAuthService represents OAuth service interface for linking accounts
type LinkOAuthService interface {
	ProviderLocation(ctx context.Context, req *goa.RequestData, identityID string, forResource string, redirectURL string) (string, error)
	Callback(ctx context.Context, req *goa.RequestData, state string, code string) (string, error)
}

type LinkConfig interface {
	GetValidRedirectURLs() string
	GetGitHubClientID() string
	GetGitHubClientDefaultScopes() string
	GetGitHubClientSecret() string
	GetOSOClusters() map[string]configuration.OSOCluster
	GetOSOClusterByURL(url string) *configuration.OSOCluster
}

// OauthProviderFactory represents oauth provider factory
type OauthProviderFactory interface {
	NewOauthProvider(ctx context.Context, identityID uuid.UUID, req *goa.RequestData, forResource string) (ProviderConfig, error)
}

// NewOauthProviderFactory returns the default Oauth provider factory.
func NewOauthProviderFactory(config LinkConfig, app application.Application) *OauthProviderFactoryService {
	service := &OauthProviderFactoryService{
		config: config,
		app:    app,
	}
	return service
}

type OauthProviderFactoryService struct {
	config LinkConfig
	app    application.Application
}

// LinkService represents service for linking accounts
type LinkService struct {
	config          LinkConfig
	app             application.Application
	providerFactory OauthProviderFactory
}

// NewLinkServiceWithFactory creates a new service for linking accounts using a specific provider factory
func NewLinkServiceWithFactory(config LinkConfig, app application.Application, factory OauthProviderFactory) LinkOAuthService {
	service := &LinkService{
		config: config,
		app:    app,
	}
	service.providerFactory = factory
	return service
}

// ProviderLocation returns a URL to OAuth 2.0 provider's consent page to be used to initiate account linking
func (service *LinkService) ProviderLocation(ctx context.Context, req *goa.RequestData, identityID string, forResource string, redirectURL string) (string, error) {
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
	oauthProvider, err := service.providerFactory.NewOauthProvider(ctx, identityUUID, req, forResources[0])
	if err != nil {
		return "", err
	}
	state := uuid.NewV4().String()
	err = oauth.SaveReferrer(ctx, service.app, state, redirectURL, nil, service.config.GetValidRedirectURLs())
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
func (service *LinkService) Callback(ctx context.Context, req *goa.RequestData, state string, code string) (string, error) {
	// validate known state
	knownReferrer, _, err := oauth.LoadReferrerAndResponseMode(ctx, service.app, state)
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

	oauthProvider, err := service.providerFactory.NewOauthProvider(ctx, identityUUID, req, forResource)
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
	err = transaction.Transactional(service.app, func(tr transaction.TransactionalResources) error {
		tokens, err := tr.ExternalTokens().LoadByProviderIDAndIdentityID(ctx, oauthProvider.ID(), identityUUID)
		if err != nil {
			return err
		}
		if len(tokens) > 0 {
			// It was re-linking. Overwrite the existing link.
			externalToken := tokens[0]
			externalToken.Token = providerToken.AccessToken
			externalToken.Username = userProfile.Username
			err = tr.ExternalTokens().Save(ctx, &externalToken)
			if err == nil {
				log.Info(ctx, map[string]interface{}{
					"provider_id":       oauthProvider.ID(),
					"identity_id":       identityID,
					"external_token_id": externalToken.ID,
				}, "An existing token found. Account re-linked & new token saved.")
			}
			return err
		}
		externalToken := provider.ExternalToken{
			Token:      providerToken.AccessToken,
			IdentityID: identityUUID,
			Scope:      oauthProvider.Scopes(),
			ProviderID: oauthProvider.ID(),
			Username:   userProfile.Username,
		}
		err = tr.ExternalTokens().Create(ctx, &externalToken)
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
		return service.ProviderLocation(ctx, req, identityID, nextResource, knownReferrer)
	}

	return knownReferrer, nil
}

// NewOauthProvider creates a new oauth provider for the given resource URL or provider alias
func (service *OauthProviderFactoryService) NewOauthProvider(ctx context.Context, identityID uuid.UUID, req *goa.RequestData, forResource string) (ProviderConfig, error) {
	authURL := rest.AbsoluteURL(req, "", nil)
	// Check if the forResource is actually a provider alias like "github" or "openshift"
	if forResource == GitHubProviderAlias {
		return NewGitHubIdentityProvider(service.config.GetGitHubClientID(), service.config.GetGitHubClientSecret(), service.config.GetGitHubClientDefaultScopes(), authURL), nil
	}
	if forResource == OpenShiftProviderAlias {
		// Look up the user's OpenShift cluster
		var clusterURL string
		err := transaction.Transactional(service.app, func(tr transaction.TransactionalResources) error {
			identities, err := tr.Identities().Query(account.IdentityFilterByID(identityID), account.IdentityWithUser())
			if err != nil {
				return err
			}
			if len(identities) == 0 {
				return errors.New("identity not found")
			}
			if identities[0].User.ID == uuid.Nil {
				return errors.New("unable to load user for identity")
			}
			clusterURL = identities[0].User.Cluster
			return nil
		})
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"identity_id": identityID,
				"err":         err,
			}, "unable to lookup user's cluster URL for identity %s", identityID)
			return nil, errs.NewUnauthorizedError(err.Error())
		}
		cluster := service.config.GetOSOClusterByURL(clusterURL)
		if cluster == nil {
			log.Error(ctx, map[string]interface{}{
				"for":         forResource,
				"cluster_url": clusterURL,
			}, "unable to find oauth config for provider alias")
			return nil, errs.NewInternalErrorFromString(ctx, fmt.Sprintf("unable to load provider for cluster URL %s", clusterURL))
		}
		return NewOpenShiftIdentityProvider(*cluster, authURL)
	}

	// Check if the forResource is some known resource URL like "https://github.com" or "https://api.starter-us-east-2.openshift.com"
	resourceURL, err := url.Parse(forResource)
	if err != nil {
		return nil, err
	}
	if resourceURL.Host == "github.com" {
		return NewGitHubIdentityProvider(service.config.GetGitHubClientID(), service.config.GetGitHubClientSecret(), service.config.GetGitHubClientDefaultScopes(), authURL), nil
	}
	cluster := service.config.GetOSOClusterByURL(forResource)
	if cluster != nil {
		return NewOpenShiftIdentityProvider(*cluster, authURL)
	}
	log.Error(ctx, map[string]interface{}{
		"for": forResource,
	}, "unable to find oauth config for resource")
	return nil, errs.NewBadParameterError("for", forResource).Expected("URL to a github.com or openshift.com resource")
}
