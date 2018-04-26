package transaction

import (
	"fmt"
	"time"

	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/fabric8-services/fabric8-auth/application/repository"
	"github.com/pkg/errors"
)

var databaseTransactionTimeout = 5 * time.Minute

func SetDatabaseTransactionTimeout(t time.Duration) {
	databaseTransactionTimeout = t
}

// TransactionalResources provides a reference to transactional resources available during a transaction
type TransactionalResources interface {
	repository.Repositories
}

// Transaction represents an existing transaction.  It provides access to transactional resources, plus methods to commit or roll back the transaction
type Transaction interface {
	TransactionalResources
	Commit() error
	Rollback() error
}

// TransactionManager manages the lifecycle of a database transaction. The transactional resources (such as repositories)
// created for the transaction object make changes inside the transaction
type TransactionManager interface {
	BeginTransaction() (Transaction, error)
}

// Transactional executes the given function in a transaction. If todo returns an error, the transaction is rolled back
func Transactional(tm TransactionManager, todo func(f TransactionalResources) error) error {
	var tx Transaction
	var err error
	if tx, err = tm.BeginTransaction(); err != nil {
		log.Error(nil, map[string]interface{}{
			"err": err,
		}, "database BeginTransaction failed!")

		return errors.WithStack(err)
	}

	return func() error {
		errorChan := make(chan error, 1)
		txTimeout := time.After(databaseTransactionTimeout)

		go func(f TransactionalResources) {
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
}
