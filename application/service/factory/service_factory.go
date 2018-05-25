package factory

import (
	"fmt"
	"github.com/fabric8-services/fabric8-auth/application/repository"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/application/transaction"
	invitationservice "github.com/fabric8-services/fabric8-auth/authorization/invitation/service"
	organizationservice "github.com/fabric8-services/fabric8-auth/authorization/organization/service"
	permissionservice "github.com/fabric8-services/fabric8-auth/authorization/permission/service"
	roleservice "github.com/fabric8-services/fabric8-auth/authorization/role/service"
	teamservice "github.com/fabric8-services/fabric8-auth/authorization/team/service"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/pkg/errors"
	"time"
)

type serviceContextImpl struct {
	repositories              repository.Repositories
	transactionalRepositories repository.Repositories
	transactionManager        transaction.TransactionManager
	inTransaction             bool
	services                  service.Services
}

func NewServiceContext(repos repository.Repositories, tm transaction.TransactionManager) context.ServiceContext {
	ctx := new(serviceContextImpl)
	ctx.repositories = repos
	ctx.transactionManager = tm
	ctx.inTransaction = false

	var sc context.ServiceContext
	sc = ctx
	ctx.services = NewServiceFactory(func() *context.ServiceContext { return &sc })
	return ctx
}

func (s *serviceContextImpl) Repositories() repository.Repositories {
	if s.inTransaction {
		return s.transactionalRepositories
	} else {
		return s.repositories
	}
}

func (s *serviceContextImpl) Services() service.Services {
	return s.services
}

func (s *serviceContextImpl) ExecuteInTransaction(todo func() error) error {
	if !s.inTransaction {
		// If we are not in a transaction already, start a new transaction
		var tx transaction.Transaction
		var err error
		if tx, err = s.transactionManager.BeginTransaction(); err != nil {
			log.Error(nil, map[string]interface{}{
				"err": err,
			}, "database BeginTransaction failed!")

			return errors.WithStack(err)
		}

		// Set the transaction flag to true
		s.inTransaction = true

		// Set the transactional repositories property
		s.transactionalRepositories = tx.(repository.Repositories)

		// Ensure changes are reverted at the end of the transaction
		defer s.endTransaction()

		return func() error {
			errorChan := make(chan error, 1)
			txTimeout := time.After(transaction.DatabaseTransactionTimeout())

			go func() {
				defer func() {
					if err := recover(); err != nil {
						errorChan <- errors.New(fmt.Sprintf("Unknown error: %v", err))
					}
				}()
				errorChan <- todo()
			}()

			select {
			case err := <-errorChan:
				if err != nil {
					log.Debug(nil, nil, "Rolling back the transaction...")
					tx.Rollback()
					log.Error(nil, map[string]interface{}{
						"err": err,
					}, "database transaction failed!")
					return errors.WithStack(err)
				}

				tx.Commit()
				log.Debug(nil, nil, "Commit the transaction!")
				return nil
			case <-txTimeout:
				log.Debug(nil, nil, "Rolling back the transaction...")
				tx.Rollback()
				log.Error(nil, nil, "database transaction timeout!")
				return errors.New("database transaction timeout!")
			}
		}()

		return err
	} else {
		// If we are in a transaction, simply execute the passed function
		return todo()
	}
}

func (s *serviceContextImpl) endTransaction() {
	s.inTransaction = false
}

type ServiceContextProducer func() *context.ServiceContext

type ServiceFactory struct {
	contextProducer ServiceContextProducer
}

func NewServiceFactory(producer ServiceContextProducer) *ServiceFactory {
	return &ServiceFactory{contextProducer: producer}
}

func (f *ServiceFactory) getContext() *context.ServiceContext {
	return f.contextProducer()
}

func (f *ServiceFactory) OrganizationService() service.OrganizationService {
	return organizationservice.NewOrganizationService(f.getContext())
}

func (f *ServiceFactory) InvitationService() service.InvitationService {
	return invitationservice.NewInvitationService(f.getContext())
}

func (f *ServiceFactory) PermissionService() service.PermissionService {
	return permissionservice.NewPermissionService(f.getContext())
}

func (f *ServiceFactory) RoleManagementService() service.RoleManagementService {
	return roleservice.NewRoleManagementService(f.getContext())
}

func (f *ServiceFactory) TeamService() service.TeamService {
	return teamservice.NewTeamService(f.getContext())
}
