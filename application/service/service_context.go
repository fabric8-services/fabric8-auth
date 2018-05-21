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
	repositories       *repository.Repositories
	transactionManager transaction.TransactionManager
	inTransaction      bool
}

func NewServiceContext(repos repository.Repositories, tm transaction.TransactionManager) ServiceContext {
	return ServiceContext{repositories: &repos, transactionManager: tm, inTransaction: false}
}

func (s *ServiceContext) Repositories() repository.Repositories {
	return *s.repositories
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

		// Replace the repositories property with the transactional repositories
		savedRepos := &s.repositories
		transactionRepos := tx.(repository.Repositories)
		s.repositories = &transactionRepos

		// Ensure changes are reverted at the end of the transaction
		defer s.endTransaction(*savedRepos)

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

func (s *ServiceContext) endTransaction(savedRepos *repository.Repositories) {
	s.inTransaction = false
	s.repositories = savedRepos
}
