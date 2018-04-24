package transaction_test

import (
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/application/transaction"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestTransaction struct {
	gormtestsupport.DBTestSuite
	app *gormapplication.GormDB
}

func TestRunTransaction(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &TestTransaction{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (test *TestTransaction) SetupTest() {
	test.DBTestSuite.SetupTest()
	test.app = gormapplication.NewGormDB(test.DB)
}

func (test *TestTransaction) TestTransactionInTime() {
	// given
	computeTime := 10 * time.Second
	// then
	err := transaction.Transactional(test.app.TransactionManager(), func(tr transaction.TransactionalResources) error {
		time.Sleep(computeTime)
		return nil
	})
	// then
	require.Nil(test.T(), err)
}

func (test *TestTransaction) TestTransactionOut() {
	// given
	computeTime := 6 * time.Minute
	transaction.SetDatabaseTransactionTimeout(5 * time.Second)
	// then
	err := transaction.Transactional(test.app.TransactionManager(), func(tr transaction.TransactionalResources) error {
		time.Sleep(computeTime)
		return nil
	})
	// then
	require.NotNil(test.T(), err)
	assert.Contains(test.T(), err.Error(), "database transaction timeout!")
}
