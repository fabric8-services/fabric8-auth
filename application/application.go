package application

import (
	"github.com/fabric8-services/fabric8-auth/application/repository"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/transaction"
)

//Application stands for a particular implementation of the business logic of our application, and provides access to the transaction management API
type Application interface {
	repository.Repositories
	service.Services
	service.Factories
	transaction.TransactionManager
}
