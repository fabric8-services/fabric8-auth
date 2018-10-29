package factory

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/authentication/subscription"
)

type SubscriptionLoaderFactoryConfiguration interface {
	GetOSORegistrationAppURL() string
	GetOSORegistrationAppAdminUsername() string
	GetOSORegistrationAppAdminToken() string
}

// NewSubscriptionLoaderFactory returns the default subscription loader factory.
func NewSubscriptionLoaderFactory(context *servicecontext.ServiceContext, config SubscriptionLoaderFactoryConfiguration) service.SubscriptionLoaderFactory {
	factory := &subscriptionLoaderFactoryImpl{
		BaseService: base.NewBaseService(context),
		config:      config,
	}
	return factory
}

type subscriptionLoaderFactoryImpl struct {
	base.BaseService
	config SubscriptionLoaderFactoryConfiguration
}

// NewSubscriptionLoader creates a new subscription loader
func (f *subscriptionLoaderFactoryImpl) NewSubscriptionLoader(ctx context.Context) subscription.SubscriptionLoader {
	return subscription.NewRemoteSubscriptionLoader(f.config)
}
