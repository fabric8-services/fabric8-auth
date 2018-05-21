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
	return s.repositories
}

func (s *ServiceContext) CreateOrJoinTransaction() error {
	if !s.inTransaction {
		var tx transaction.Transaction
		var err error
		if tx, err = s.transactionManager.BeginTransaction(); err != nil {
			log.Error(nil, map[string]interface{}{
				"err": err,
			}, "database BeginTransaction failed!")

			return errors.WithStack(err)
		}

		return func() error {
			errorChan := make(chan error, 1)
			txTimeout := time.After(transaction.databaseTransactionTimeout)

			go func(f transaction.TransactionalResources) {
				defer func() {
					if err := recover(); err != nil {
						errorChan <- errors.New(fmt.Sprintf("Unknown error: %v", err))
					}
				}()
				errorChan <- todo(tx)
			}(tx)

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

		savedRepos := &s.repositories
		defer s.endTransaction(*savedRepos)
		s.inTransaction = true

		transaction.Transactional(s.transactionManager, func(res transaction.TransactionalResources) error {
			repos := res.(repository.Repositories)
			s.repositories = &repos
			return nil
		})

	}
}

func (s *ServiceContext) endTransaction(savedRepos *repository.Repositories) {
	s.inTransaction = false
	s.repositories = savedRepos
}
