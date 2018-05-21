package registry

import (
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	"reflect"
)

type ServiceConstructor func() interface{}

var serviceRegister = make(map[reflect.Type]ServiceConstructor)

func NewService(serviceType reflect.Type, serviceContext *service.ServiceContext) interface{} {
	c := serviceRegister[serviceType]
	value := c()
	svc := value.(base.BaseService)
	svc.Init(serviceContext)
	return svc
}

func RegisterService(serviceType reflect.Type, constructor ServiceConstructor) {
	serviceRegister[serviceType] = constructor
}
