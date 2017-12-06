package link

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/configuration"
	errs "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-auth/token/oauth"
	"github.com/fabric8-services/fabric8-auth/token/provider"

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
	IsTLSInsecureSkipVerify() bool
	GetOSOClusters() map[string]configuration.OSOCluster
}

// OauthProviderFactory represents oauth provider factory
type OauthProviderFactory interface {
	NewOauthProvider(ctx context.Context, req *goa.RequestData, forResource string) (ProviderConfig, error)
}

// NewOauthProviderFactory returns the default Oauth provider factory.
func NewOauthProviderFactory(config LinkConfig) *OauthProviderFactoryService {
	service := &OauthProviderFactoryService{
		config: config,
	}
	return service
}

type OauthProviderFactoryService struct {
	config LinkConfig
}

// LinkService represents service for linking accounts
type LinkService struct {
	config          LinkConfig
	db              application.DB
	providerFactory OauthProviderFactory
}

// NewLinkServiceWithFactory creates a new service for linking accounts using a specific provider factory
func NewLinkServiceWithFactory(config LinkConfig, db application.DB, factory OauthProviderFactory) LinkOAuthService {
	service := &LinkService{
		config: config,
		db:     db,
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

	oauthProvider, err := service.providerFactory.NewOauthProvider(ctx, req, forResources[0])
	if err != nil {
		return "", err
	}
	stateID := uuid.NewV4()
	err = oauth.SaveReferrer(ctx, service.db, stateID, redirectURL, service.config.GetValidRedirectURLs())
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"redirect_url": redirectURL,
			"for":          forResource,
			"err":          err,
		}, "unable to save the state")
		return "", err
	}

	return oauthProvider.AuthCodeURL(stateID.String(), oauth2.AccessTypeOnline), nil
}

// Callback returns a redirect URL after callback from an external oauth2 resource provider such as GitHub during user's account linking
func (service *LinkService) Callback(ctx context.Context, req *goa.RequestData, state string, code string) (string, error) {
	// validate known state
	knownReferrer, err := oauth.LoadReferrer(ctx, service.db, state)
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

	oauthProvider, err := service.providerFactory.NewOauthProvider(ctx, req, forResource)
	if err != nil {
		return "", err
	}

	if service.config.IsTLSInsecureSkipVerify() {
		// For testing only.
		log.Warn(ctx, map[string]interface{}{
			"code":        code,
			"state":       state,
			"provider_id": oauthProvider.ID(),
			"identity_id": identityID,
		}, "TLS verification is disabled!")
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		sslcli := &http.Client{Transport: tr}
		ctx = context.WithValue(ctx, oauth2.HTTPClient, sslcli)
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
	err = application.Transactional(service.db, func(appl application.Application) error {
		tokens, err := appl.ExternalTokens().LoadByProviderIDAndIdentityID(ctx, oauthProvider.ID(), identityUUID)
		if err != nil {
			return err
		}
		if len(tokens) > 0 {
			// It was re-linking. Overwrite the existing link.
			externalToken := tokens[0]
			externalToken.Token = providerToken.AccessToken
			externalToken.Username = userProfile.Username
			err = appl.ExternalTokens().Save(ctx, &externalToken)
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
		err = appl.ExternalTokens().Create(ctx, &externalToken)
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

// NewOauthProvider creates a new oauth provider for the given resource URL
func (service *OauthProviderFactoryService) NewOauthProvider(ctx context.Context, req *goa.RequestData, forResource string) (ProviderConfig, error) {
	authURL := rest.AbsoluteURL(req, "")
	resourceURL, err := url.Parse(forResource)
	if err != nil {
		return nil, err
	}
	if resourceURL.Host == "github.com" {
		return NewGitHubIdentityProvider(service.config.GetGitHubClientID(), service.config.GetGitHubClientSecret(), service.config.GetGitHubClientDefaultScopes(), authURL), nil
	}
	clusters := service.config.GetOSOClusters()
	for apiURL, cluster := range clusters {
		if strings.HasPrefix(forResource, apiURL) {
			return NewOpenShiftIdentityProvider(cluster, authURL)
		}
	}
	log.Error(ctx, map[string]interface{}{
		"for": forResource,
	}, "unable to find oauth config for resource")
	return nil, errs.NewBadParameterError("for", forResource).Expected("URL to a github.com or openshift.com resource")
}
