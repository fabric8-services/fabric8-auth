package service

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/authentication/provider"
	"golang.org/x/oauth2"
)

// NewIdentityProviderFactory returns the default Oauth provider factory.
func NewIdentityProviderFactory(context servicecontext.ServiceContext) service.IdentityProviderFactory {
	factory := &identityProviderFactoryImpl{
		BaseService: base.NewBaseService(context),
	}
	return factory
}

type identityProviderFactoryImpl struct {
	base.BaseService
}

// NewIdentityProvider creates a new identity provider based on the specified configuration
func (f *identityProviderFactoryImpl) NewIdentityProvider(ctx context.Context, config provider.IdentityProviderConfiguration) provider.IdentityProvider {
	provider := &provider.DefaultIdentityProvider{}
	provider.ProfileURL = config.GetOAuthProviderEndpointUserInfo()
	provider.ClientID = config.GetOAuthProviderClientID()
	provider.ClientSecret = config.GetOAuthProviderClientSecret()
	provider.Scopes = []string{"user:email"}
	provider.Endpoint = oauth2.Endpoint{AuthURL: config.GetOAuthProviderEndpointAuth(), TokenURL: config.GetOAuthProviderEndpointToken()}
	return provider
}
