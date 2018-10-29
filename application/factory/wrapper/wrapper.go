package wrapper

import (
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/configuration"
)

type Wrapper interface {
	WrapFactory(identifier string, constructor FactoryWrapperConstructor, initializer FactoryWrapperInitializer)
}

type FactoryWrapperConstructor = func(servicecontext.ServiceContext, *configuration.ConfigurationData) FactoryWrapper
type FactoryWrapperInitializer = func(FactoryWrapper)

type FactoryWrapper interface {
	Configuration() *configuration.ConfigurationData
	ServiceContext() servicecontext.ServiceContext
	SetFactory(factory interface{})
	Factory() interface{}
}

type BaseFactoryWrapper struct {
	context servicecontext.ServiceContext
	config  *configuration.ConfigurationData
	factory interface{}
}

func NewBaseFactoryWrapper(context servicecontext.ServiceContext, config *configuration.ConfigurationData) *BaseFactoryWrapper {
	return &BaseFactoryWrapper{
		context: context,
		config:  config,
	}
}

func (w *BaseFactoryWrapper) Configuration() *configuration.ConfigurationData {
	return w.config
}

func (w *BaseFactoryWrapper) ServiceContext() servicecontext.ServiceContext {
	return w.context
}

func (w *BaseFactoryWrapper) SetFactory(factory interface{}) {
	w.factory = factory
}

func (w *BaseFactoryWrapper) Factory() interface{} {
	return w.factory
}
