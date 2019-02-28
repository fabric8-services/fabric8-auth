package factory

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/authentication/provider"
	errs "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	uuid "github.com/satori/go.uuid"
)

// NewLinkingProviderFactory returns the default Linking provider factory.
func NewLinkingProviderFactory(context servicecontext.ServiceContext, config provider.LinkingProviderConfiguration) service.LinkingProviderFactory {
	factory := &linkingProviderFactoryImpl{
		BaseService: base.NewBaseService(context),
		config:      config,
	}
	return factory
}

type linkingProviderFactoryImpl struct {
	base.BaseService
	config provider.LinkingProviderConfiguration
}

// NewLinkingProvider creates a new linking provider for the given resource URL or provider alias
func (f *linkingProviderFactoryImpl) NewLinkingProvider(ctx context.Context, identityID uuid.UUID, authURL string, forResource string) (provider.LinkingProvider, error) {
	// Check if the forResource is actually a provider alias like "github" or "openshift"
	if forResource == provider.GitHubProviderAlias {
		return provider.NewGitHubIdentityProvider(f.config.GetGitHubClientID(), f.config.GetGitHubClientSecret(), f.config.GetGitHubClientDefaultScopes(), authURL), nil
	}
	if forResource == provider.OpenShiftProviderAlias {
		// Look up the user's OpenShift cluster
		var clusterURL string
		err := f.ExecuteInTransaction(func() error {
			identities, err := f.Repositories().Identities().Query(account.IdentityFilterByID(identityID), account.IdentityWithUser())
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
			log.Debug(ctx, map[string]interface{}{"cluster_url": clusterURL, "identity_id": identityID}, "looking up cluster for identity")
			return nil

		})
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"identity_id": identityID,
				"err":         err,
			}, "unable to lookup user's cluster URL for identity %s", identityID)
			return nil, errs.NewUnauthorizedError(err.Error())
		}

		cluster, err := f.Services().ClusterService().ClusterByURL(ctx, clusterURL)
		if err != nil {
			return nil, errs.NewInternalError(ctx, err)
		}
		if cluster == nil {
			log.Error(ctx, map[string]interface{}{
				"for":         forResource,
				"cluster_url": clusterURL,
			}, "unable to find oauth config for provider alias")
			return nil, errs.NewInternalErrorFromString(ctx, fmt.Sprintf("unable to load provider for cluster URL %s", clusterURL))
		}
		return provider.NewOpenShiftIdentityProvider(*cluster, authURL)
	}

	// Check if the forResource is some known resource URL like "https://github.com" or "https://api.starter-us-east-2.openshift.com"
	resourceURL, err := url.Parse(forResource)
	if err != nil {
		return nil, err
	}
	if resourceURL.Host == "github.com" {
		return provider.NewGitHubIdentityProvider(f.config.GetGitHubClientID(), f.config.GetGitHubClientSecret(),
			f.config.GetGitHubClientDefaultScopes(), authURL), nil
	}
	cluster, err := f.Services().ClusterService().ClusterByURL(ctx, forResource)
	if err != nil {
		return nil, errs.NewInternalError(ctx, err)
	}
	if cluster != nil {
		return provider.NewOpenShiftIdentityProvider(*cluster, authURL)
	}
	log.Error(ctx, map[string]interface{}{
		"for": forResource,
	}, "unable to find oauth config for resource")
	return nil, errs.NewBadParameterError("for", forResource).Expected("URL to a github.com or openshift.com resource")
}
