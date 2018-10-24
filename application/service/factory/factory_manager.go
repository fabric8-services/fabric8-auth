package factory

import (
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/context"
	providerservice "github.com/fabric8-services/fabric8-auth/authentication/provider/service"
	"github.com/fabric8-services/fabric8-auth/configuration"
)

type FactoryManager struct {
	contextProducer ServiceContextProducer
	config          *configuration.ConfigurationData
	overrides       map[string]func() interface{}
}

func NewFactoryManager(producer ServiceContextProducer, config *configuration.ConfigurationData) *FactoryManager {
	return &FactoryManager{contextProducer: producer, config: config, overrides: make(map[string]func() interface{})}
}

func (f *FactoryManager) getContext() context.ServiceContext {
	return f.contextProducer()
}

func (f *FactoryManager) ReplaceFactory(factory string, constructor func() interface{}) {
	f.overrides[factory] = constructor
}

func (f *FactoryManager) ResetFactories() {
	for k := range f.overrides {
		delete(f.overrides, k)
	}
}

func (f *FactoryManager) LinkingProviderFactory() service.LinkingProviderFactory {
	if cons, ok := f.overrides[service.FACTORY_TYPE_LINKING_PROVIDER]; ok {
		return cons().(service.LinkingProviderFactory)
	}
	return providerservice.NewLinkingProviderFactory(f.getContext(), f.config)
}
