package context

import (
	"github.com/fabric8-services/fabric8-auth/application/repository"
	"github.com/fabric8-services/fabric8-auth/application/service"
)

type ServiceContext interface {
	Repositories() repository.Repositories
	Services() service.Services
	ExecuteInTransaction(todo func() error) error
}
