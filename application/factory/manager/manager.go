package factory

import (
	"github.com/fabric8-services/fabric8-auth/application/factory/wrapper"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/context"
	providerfactory "github.com/fabric8-services/fabric8-auth/authentication/provider/factory"
	subscriptionfactory "github.com/fabric8-services/fabric8-auth/authentication/subscription/factory"
	clusterfactory "github.com/fabric8-services/fabric8-auth/cluster/factory"
	"github.com/fabric8-services/fabric8-auth/configuration"
)

type WrapperDefinition interface {
	GetConstructor() wrapper.FactoryWrapperConstructor
	GetInitializer() wrapper.FactoryWrapperInitializer
}

type FactoryWrappers interface {
	RegisterWrapper(identifier string, constructor wrapper.FactoryWrapperConstructor, initializer wrapper.FactoryWrapperInitializer)
	GetWrapper(identifier string) WrapperDefinition
	ResetWrappers()
}

type wrapperDef struct {
	constructor wrapper.FactoryWrapperConstructor
	initializer wrapper.FactoryWrapperInitializer
}

func (d wrapperDef) GetConstructor() wrapper.FactoryWrapperConstructor {
	return d.constructor
}

func (d wrapperDef) GetInitializer() wrapper.FactoryWrapperInitializer {
	return d.initializer
}

type factoryWrappersImpl struct {
	wrappers map[string]wrapperDef
}

func NewFactoryWrappers() FactoryWrappers {
	return &factoryWrappersImpl{wrappers: make(map[string]wrapperDef)}
}

// disabledFactoryWrappers should be used when no wrapper support is desired, e.g. at normal runtime
type disabledFactoryWrappers struct {}

func (w *disabledFactoryWrappers) RegisterWrapper(identifier string, constructor wrapper.FactoryWrapperConstructor, initializer wrapper.FactoryWrapperInitializer) {}
func (w *disabledFactoryWrappers) GetWrapper(identifier string) WrapperDefinition { return nil }
func (w *disabledFactoryWrappers) ResetWrappers() {}

func NewDisabledFactoryWrappers() FactoryWrappers {
	return &disabledFactoryWrappers{}
}

func (w *factoryWrappersImpl) RegisterWrapper(identifier string, constructor wrapper.FactoryWrapperConstructor, initializer wrapper.FactoryWrapperInitializer) {
	w.wrappers[identifier] = wrapperDef{
		constructor: constructor,
		initializer: initializer,
	}
}

func (w *factoryWrappersImpl) GetWrapper(identifier string) WrapperDefinition {
	if def, ok := w.wrappers[identifier]; ok {
		return def
	}
	return nil
}

func (w *factoryWrappersImpl) ResetWrappers() {
	for k := range w.wrappers {
		delete(w.wrappers, k)
	}
}

type Manager struct {
	contextProducer context.ServiceContextProducer
	config          *configuration.ConfigurationData
	wrappers        FactoryWrappers
}

func NewManager(producer context.ServiceContextProducer, config *configuration.ConfigurationData, wrappers FactoryWrappers) *Manager {
	return &Manager{contextProducer: producer, config: config, wrappers: wrappers}
}

func (f *Manager) getContext() context.ServiceContext {
	return f.contextProducer()
}

func (f *Manager) ClusterCacheFactory() service.ClusterCacheFactory {
	def := f.wrappers.GetWrapper(service.FACTORY_TYPE_CLUSTER_CACHE)

	if def != nil {
		// Create the wrapper first
		w := def.GetConstructor()(f.getContext(), f.config)

		// Initialize the wrapper
		if def.GetInitializer() != nil {
			def.GetInitializer()(w)
		}

		// Create the factory and set it in the wrapper
		w.SetFactory(clusterfactory.NewClusterCacheFactory(w.ServiceContext(), w.Configuration()))

		// Return the wrapper as the factory
		return w.(service.ClusterCacheFactory)
	}

	return clusterfactory.NewClusterCacheFactory(f.getContext(), f.config)
}

func (f *Manager) IdentityProviderFactory() service.IdentityProviderFactory {
	def := f.wrappers.GetWrapper(service.FACTORY_TYPE_IDENTITY_PROVIDER)

	if def != nil {
		// Create the wrapper first
		w := def.GetConstructor()(f.getContext(), f.config)

		// Initialize the wrapper
		if def.GetInitializer() != nil {
			def.GetInitializer()(w)
		}

		// Create the factory and set it in the wrapper
		w.SetFactory(providerfactory.NewIdentityProviderFactory(w.ServiceContext()))

		// Return the wrapper as the factory
		return w.(service.IdentityProviderFactory)
	}

	return providerfactory.NewIdentityProviderFactory(f.getContext())
}

func (f *Manager) LinkingProviderFactory() service.LinkingProviderFactory {
	def := f.wrappers.GetWrapper(service.FACTORY_TYPE_LINKING_PROVIDER)

	if def != nil {
		// Create the wrapper first
		w := def.GetConstructor()(f.getContext(), f.config)

		// Initialize the wrapper
		if def.GetInitializer() != nil {
			def.GetInitializer()(w)
		}

		// Create the factory and set it in the wrapper
		w.SetFactory(providerfactory.NewLinkingProviderFactory(w.ServiceContext(), w.Configuration()))

		// Return the wrapper as the factory
		return w.(service.LinkingProviderFactory)
	}

	return providerfactory.NewLinkingProviderFactory(f.getContext(), f.config)
}

func (f *Manager) SubscriptionLoaderFactory() service.SubscriptionLoaderFactory {
	def := f.wrappers.GetWrapper(service.FACTORY_TYPE_SUBSCRIPTION_LOADER)

	if def != nil {
		// Create the wrapper first
		w := def.GetConstructor()(f.getContext(), f.config)

		// Initialize the wrapper
		if def.GetInitializer() != nil {
			def.GetInitializer()(w)
		}

		// Create the factory and set it in the wrapper
		w.SetFactory(subscriptionfactory.NewSubscriptionLoaderFactory(w.ServiceContext(), w.Configuration()))

		// Return the wrapper as the factory
		return w.(service.SubscriptionLoaderFactory)
	}

	return subscriptionfactory.NewSubscriptionLoaderFactory(f.getContext(), f.config)
}
