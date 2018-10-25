package factory

import (
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/context"
	providerfactory "github.com/fabric8-services/fabric8-auth/authentication/provider/factory"
	"github.com/fabric8-services/fabric8-auth/configuration"
)

type FactoryWrapperConstructor = func(context.ServiceContext, *configuration.ConfigurationData) FactoryWrapper
type FactoryWrapperInitializer = func(FactoryWrapper)

type wrapperDef struct {
	constructor FactoryWrapperConstructor
	initializer FactoryWrapperInitializer
}

type FactoryManager struct {
	contextProducer ServiceContextProducer
	config          *configuration.ConfigurationData
	wrappers        map[string]wrapperDef
}

type FactoryWrapper interface {
	Configuration() *configuration.ConfigurationData
	ServiceContext() context.ServiceContext
	SetFactory(factory interface{})
	Factory() interface{}
}

type BaseFactoryWrapper struct {
	context context.ServiceContext
	config  *configuration.ConfigurationData
	factory interface{}
}

func NewBaseFactoryWrapper(context context.ServiceContext, config *configuration.ConfigurationData) *BaseFactoryWrapper {
	return &BaseFactoryWrapper{
		context: context,
		config:  config,
	}
}

func (w *BaseFactoryWrapper) Configuration() *configuration.ConfigurationData {
	return w.config
}

func (w *BaseFactoryWrapper) ServiceContext() context.ServiceContext {
	return w.context
}

func (w *BaseFactoryWrapper) SetFactory(factory interface{}) {
	w.factory = factory
}

func (w *BaseFactoryWrapper) Factory() interface{} {
	return w.factory
}

func NewFactoryManager(producer ServiceContextProducer, config *configuration.ConfigurationData) *FactoryManager {
	return &FactoryManager{contextProducer: producer, config: config, wrappers: make(map[string]wrapperDef)}
}

func (f *FactoryManager) getContext() context.ServiceContext {
	return f.contextProducer()
}

func (f *FactoryManager) WrapFactory(identifier string, constructor FactoryWrapperConstructor, initializer FactoryWrapperInitializer) {
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
	var wrapper FactoryWrapper

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
