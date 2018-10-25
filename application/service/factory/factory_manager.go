package factory

import (
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/application/service/wrapper"
	providerfactory "github.com/fabric8-services/fabric8-auth/authentication/provider/factory"
	"github.com/fabric8-services/fabric8-auth/configuration"
)

type wrapperDef struct {
	constructor wrapper.FactoryWrapperConstructor
	initializer wrapper.FactoryWrapperInitializer
}

type FactoryManager struct {
	contextProducer ServiceContextProducer
	config          *configuration.ConfigurationData
	wrappers        map[string]wrapperDef
}

func NewFactoryManager(producer ServiceContextProducer, config *configuration.ConfigurationData) *FactoryManager {
	return &FactoryManager{contextProducer: producer, config: config, wrappers: make(map[string]wrapperDef)}
}

func (f *FactoryManager) getContext() context.ServiceContext {
	return f.contextProducer()
}

func (f *FactoryManager) WrapFactory(identifier string, constructor wrapper.FactoryWrapperConstructor, initializer wrapper.FactoryWrapperInitializer) {
	f.wrappers[identifier] = wrapperDef{
		constructor: constructor,
		initializer: initializer,
	}
}

func (f *FactoryManager) ResetFactories() {
	for k := range f.wrappers {
		delete(f.wrappers, k)
	}
}

func (f *FactoryManager) LinkingProviderFactory() service.LinkingProviderFactory {
	var wrapper wrapper.FactoryWrapper

	if def, ok := f.wrappers[service.FACTORY_TYPE_LINKING_PROVIDER]; ok {
		// Create the wrapper first
		wrapper = def.constructor(f.getContext(), f.config)

		// Initialize the wrapper
		if def.initializer != nil {
			def.initializer(wrapper)
		}

		// Create the factory and set it in the wrapper
		wrapper.SetFactory(providerfactory.NewLinkingProviderFactory(wrapper.ServiceContext(), wrapper.Configuration()))

		// Return the wrapper as the factory
		return wrapper.(service.LinkingProviderFactory)
	}

	return providerfactory.NewLinkingProviderFactory(f.getContext(), f.config)
}
