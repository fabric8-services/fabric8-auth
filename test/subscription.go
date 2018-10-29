package test

import (
	"context"

	"github.com/fabric8-services/fabric8-auth/application/factory/wrapper"
	svc "github.com/fabric8-services/fabric8-auth/application/service"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/authentication/subscription"
	"github.com/fabric8-services/fabric8-auth/configuration"
)

//----------------------------------------------------------------------------------------------------------------------
//
// Dummy Subscription Loader
//
//----------------------------------------------------------------------------------------------------------------------

type dummySubscriptionLoaderFactory interface {
	setSubscriptionLoader(load subscription.SubscriptionLoader)
}

type dummySubscriptionLoaderFactoryImpl struct {
	wrapper.BaseFactoryWrapper
	loader subscription.SubscriptionLoader
}

func ActivateDummySubscriptionLoaderFactory(w wrapper.Wrapper, loader subscription.SubscriptionLoader) {
	w.WrapFactory(svc.FACTORY_TYPE_SUBSCRIPTION_LOADER,
		func(ctx servicecontext.ServiceContext, config *configuration.ConfigurationData) wrapper.FactoryWrapper {
			baseFactoryWrapper := wrapper.NewBaseFactoryWrapper(ctx, config)
			return &dummySubscriptionLoaderFactoryImpl{
				BaseFactoryWrapper: *baseFactoryWrapper,
			}
		},
		func(w wrapper.FactoryWrapper) {
			w.(dummySubscriptionLoaderFactory).setSubscriptionLoader(loader)
		})
}

func (f *dummySubscriptionLoaderFactoryImpl) setSubscriptionLoader(loader subscription.SubscriptionLoader) {
	f.loader = loader
}

func (f *dummySubscriptionLoaderFactoryImpl) NewSubscriptionLoader(ctx context.Context) subscription.SubscriptionLoader {
	return f.loader
}

type DummySubscriptionLoader struct {
	Status string
	Err    error
	APIURL string
}

func NewDummySubscriptionLoader() *DummySubscriptionLoader {
	return &DummySubscriptionLoader{}
}

func (l *DummySubscriptionLoader) LoadSubscriptions(ctx context.Context, username string) (*subscription.Subscriptions, error) {
	if l.Err != nil {
		return nil, l.Err
	}

	subs := &subscription.Subscriptions{
		Subscriptions: []subscription.Subscription{
			{
				Status: l.Status,
				Plan: subscription.Plan{
					Service: subscription.Service{
						APIURL: l.APIURL,
					},
				},
			},
		},
	}

	return subs, nil
}
