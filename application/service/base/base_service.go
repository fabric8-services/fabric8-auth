package base

import (
	"github.com/fabric8-services/fabric8-auth/application/repository"
	"github.com/fabric8-services/fabric8-auth/application/service"
)

// BaseService provides transaction control and other common features for service implementations
type BaseService struct {
	serviceContext *service.ServiceContext
}

func (s *BaseService) Init(serviceContext *service.ServiceContext) interface{} {
	s.serviceContext = serviceContext
	return *s
}

func (s *BaseService) Repositories() repository.Repositories {
	return s.serviceContext.Repositories()
}

func (s *BaseService) Services() *service.Services {
	return nil
}

func (s *BaseService) Transactional(todo func() error) error {
	s.serviceContext.CreateOrJoinTransaction()
	return todo()
}
