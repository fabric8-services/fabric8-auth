package factory

import (
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/authentication/provider"
	providerfactory "github.com/fabric8-services/fabric8-auth/authentication/provider/factory"
	"github.com/fabric8-services/fabric8-auth/configuration"
)

type FactoryManager struct {
	contextProducer ServiceContextProducer
	config          *configuration.ConfigurationData
	overrides       map[string]interface{}
	configs         map[string]interface{}
}

func NewFactoryManager(producer ServiceContextProducer, config *configuration.ConfigurationData) *FactoryManager {
	return &FactoryManager{contextProducer: producer, config: config, overrides: make(map[string]interface{})}
}

func (f *FactoryManager) getContext() context.ServiceContext {
	return f.contextProducer()
}

func (f *FactoryManager) ReplaceFactory(identifier string, factory interface{}) {
	f.overrides[identifier] = factory
}

func (f *FactoryManager) OverrideFactoryConfig(identifier string, config interface{}) {
	f.configs[identifier] = config
}

func (f *FactoryManager) ResetFactories() {
	for k := range f.overrides {
		delete(f.overrides, k)
	}
	for k := range f.configs {
		delete(f.configs, k)
	}
}

func (f *FactoryManager) LinkingProviderFactory() service.LinkingProviderFactory {
	if cons, ok := f.overrides[service.FACTORY_TYPE_LINKING_PROVIDER]; ok {
		return cons.(service.LinkingProviderFactory)
	}
	if conf, ok := f.configs[service.FACTORY_TYPE_LINKING_PROVIDER]; ok {
		return providerfactory.NewLinkingProviderFactory(f.getContext(), conf.(provider.LinkingProviderConfig))
	}
	return providerfactory.NewLinkingProviderFactory(f.getContext(), f.config)
}
