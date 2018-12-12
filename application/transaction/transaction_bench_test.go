package transaction_test

import (
	"database/sql"
	"testing"

	_ "github.com/lib/pq"
	"github.com/satori/go.uuid"
	"golang.org/x/net/context"

	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/application/transaction"
	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormsupport/cleaner"
	gormbench "github.com/fabric8-services/fabric8-auth/gormtestsupport/benchmark"
	"github.com/fabric8-services/fabric8-auth/migration"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
)

type BenchTransactional struct {
	gormbench.DBBenchSuite
	clean    func()
	repo     account.IdentityRepository
	ctx      context.Context
	app      application.Application
	dbPq     *sql.DB
	identity *account.Identity
}

func BenchmarkRunTransactional(b *testing.B) {
	testsupport.Run(b, &BenchTransactional{DBBenchSuite: gormbench.NewDBBenchSuite("../config.yaml")})
}

// SetupSuite overrides the DBTestSuite's function but calls it before doing anything else
// The SetupSuite method will run before the tests in the suite are run.
// It sets up a database connection for all the tests in this suite without polluting global space.
func (s *BenchTransactional) SetupSuite() {
	s.DBBenchSuite.SetupSuite()
	s.ctx = migration.NewMigrationContext(context.Background())
}

func (s *BenchTransactional) SetupBenchmark() {
	s.clean = cleaner.DeleteCreatedEntities(s.DB)
	s.repo = account.NewIdentityRepository(s.DB)
	s.app = gormapplication.NewGormDB(s.DB, s.Configuration, nil)

	s.identity = &account.Identity{
		ID:           uuid.NewV4(),
		Username:     "BenchmarkTransactionalTestIdentity",
		ProviderType: account.DefaultIDP}

	err := s.repo.Create(s.ctx, s.identity)
	if err != nil {
		s.B().Fail()
	}
}

func (s *BenchTransactional) TearDownBenchmark() {
	s.clean()
}

func (s *BenchTransactional) transactionLoadSpace() {
	err := transaction.Transactional(s.app, func(tr transaction.TransactionalResources) error {
		_, err := s.repo.Load(s.ctx, s.identity.ID)
		return err
	})
	if err != nil {
		s.B().Fail()
	}
}

func (s *BenchTransactional) BenchmarkApplTransaction() {
	s.B().ResetTimer()
	s.B().ReportAllocs()
	for n := 0; n < s.B().N; n++ {
		s.transactionLoadSpace()
	}
}
