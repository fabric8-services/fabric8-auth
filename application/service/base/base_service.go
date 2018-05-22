package base

import (
	"github.com/fabric8-services/fabric8-auth/application/repository"
	"github.com/fabric8-services/fabric8-auth/application/service"
)

// BaseService provides transaction control and other common features for service implementations
type BaseService struct {
	serviceContext service.ServiceContext
}

func NewBaseService(context *service.ServiceContext) BaseService {
	return BaseService{serviceContext: *context}
}

func (s *BaseService) Repositories() repository.Repositories {
	return s.serviceContext.Repositories()
}

func (s *BaseService) Services() *service.Services {
	return nil
}

func (s *BaseService) Transactional(todo func() error) error {
	err := s.serviceContext.ExecuteInTransaction(todo)
	return err
}
