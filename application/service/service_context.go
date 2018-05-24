package service

import (
	"fmt"
	"github.com/fabric8-services/fabric8-auth/application/repository"
	"github.com/fabric8-services/fabric8-auth/application/transaction"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/pkg/errors"
	"time"
)

type ServiceContext struct {
	repositories              repository.Repositories
	transactionalRepositories repository.Repositories
	transactionManager        transaction.TransactionManager
	inTransaction             bool
	services                  Services
}

func NewServiceContext(repos repository.Repositories, tm transaction.TransactionManager) *ServiceContext {
	ctx := new(ServiceContext)
	ctx.repositories = repos
	ctx.transactionManager = tm
	ctx.inTransaction = false
	return ctx
}

func (s *ServiceContext) Repositories() repository.Repositories {
	if s.inTransaction {
		return s.transactionalRepositories
	} else {
		return s.repositories
	}
}

func (s *ServiceContext) Services() Services {
	return s.services
}

func (s *ServiceContext) ExecuteInTransaction(todo func() error) error {
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

func (s *ServiceContext) endTransaction() {
	s.inTransaction = false
}
