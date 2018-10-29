package factory

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/authentication/provider"
)

// NewIdentityProviderFactory returns the default Oauth provider factory.
func NewIdentityProviderFactory(context *servicecontext.ServiceContext) service.IdentityProviderFactory {
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
	return provider.NewIdentityProvider(config)
}
