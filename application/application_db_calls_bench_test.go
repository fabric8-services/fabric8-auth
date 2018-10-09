package application_test

import (
	"database/sql"
	"testing"

	_ "github.com/lib/pq"
	"golang.org/x/net/context"

	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/gormsupport/cleaner"
	gormbench "github.com/fabric8-services/fabric8-auth/gormtestsupport/benchmark"
	"github.com/fabric8-services/fabric8-auth/migration"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/jinzhu/gorm"
	uuid "github.com/satori/go.uuid"
)

type Identity struct {
	gorm.Model
	gormsupport.Lifecycle
	ID       uuid.UUID
	Username string
}

type BenchDbOperations struct {
	gormbench.DBBenchSuite
	clean    func()
	repo     account.IdentityRepository
	ctx      context.Context
	dbPq     *sql.DB
	identity *account.Identity
}

func BenchmarkRunDbOperations(b *testing.B) {
	testsupport.Run(b, &BenchDbOperations{DBBenchSuite: gormbench.NewDBBenchSuite("../config.yaml")})
}

// SetupSuite overrides the DBTestSuite's function but calls it before doing anything else
// The SetupSuite method will run before the tests in the suite are run.
// It sets up a database connection for all the tests in this suite without polluting global space.
func (s *BenchDbOperations) SetupSuite() {
	s.DBBenchSuite.SetupSuite()
	s.ctx = migration.NewMigrationContext(context.Background())
	var err error
	s.dbPq, err = sql.Open("postgres", "host=localhost port=5432 user=postgres password=mysecretpassword dbname=postgres sslmode=disable connect_timeout=5")
	if err != nil {
		s.B().Fail()
	}
	s.dbPq.SetMaxOpenConns(10)
	s.dbPq.SetMaxIdleConns(10)
	s.dbPq.SetConnMaxLifetime(0)
}

func (s *BenchDbOperations) SetupBenchmark() {
	s.clean = cleaner.DeleteCreatedEntities(s.DB)
	s.repo = account.NewIdentityRepository(s.DB)

	s.identity = &account.Identity{
		ID:           uuid.NewV4(),
		Username:     "BenchmarkTestIdentity",
		ProviderType: account.KeycloakIDP}

	err := s.repo.Create(s.ctx, s.identity)
	if err != nil {
		s.B().Fail()
	}
}

func (s *BenchDbOperations) TearDownBenchmark() {
	s.clean()
}

func (s *BenchDbOperations) BenchmarkPqSelectOneQuery() {
	s.B().ResetTimer()
	s.B().ReportAllocs()
	todo := func() {
		result, err := s.dbPq.Query("SELECT 1")
		defer result.Close()
		if err != nil {
			s.B().Fail()
		}
		for result.Next() {
		}
	}
	for n := 0; n < s.B().N; n++ {
		todo()
	}
}

func (s *BenchDbOperations) BenchmarkGormSelectOneQuery() {
	s.B().ResetTimer()
	s.B().ReportAllocs()
	todo := func() {
		result, err := s.DB.Raw("select 1").Rows()
		defer result.Close()
		if err != nil {
			s.B().Fail()
		}
		for result.Next() {
		}
	}
	for n := 0; n < s.B().N; n++ {
		todo()
	}
}

func (s *BenchDbOperations) BenchmarkGormSelectUsernameFirst() {
	var idn Identity
	s.B().ResetTimer()
	s.B().ReportAllocs()
	for n := 0; n < s.B().N; n++ {
		db := s.DB.Select("username")
		db.Where("id=?", s.identity.ID.String()).First(&idn)
	}
}

func (s *BenchDbOperations) BenchmarkGormSelectUsernameFind() {
	var idn Identity
	s.B().ResetTimer()
	s.B().ReportAllocs()
	for n := 0; n < s.B().N; n++ {
		db := s.DB.Table("identities").Select("username")
		db.Where("id=?", s.identity.ID.String()).Find(&idn)
	}
}

func (s *BenchDbOperations) BenchmarkGormSelectUsernameRaw() {
	s.B().ResetTimer()
	s.B().ReportAllocs()
	todo := func() {
		var names []string
		result, err := s.DB.Raw("select username from identities where id=?", s.identity.ID.String()).Rows()
		if err != nil {
			s.B().Fail()
		}
		defer result.Close()
		for result.Next() {
			var username string
			result.Scan(&username)
			names = append(names, username)
		}
	}
	for n := 0; n < s.B().N; n++ {
		todo()
	}
}

func (s *BenchDbOperations) BenchmarkPqSelectUsernamePreparedStatement() {
	queryStmt, err := s.dbPq.Prepare("SELECT username FROM identities WHERE id=$1")
	if err != nil {
		s.B().Fail()
	}
	var idn account.Identity
	s.B().ResetTimer()
	s.B().ReportAllocs()
	for n := 0; n < s.B().N; n++ {
		err = queryStmt.QueryRow(s.identity.ID.String()).Scan(&idn.Username)
		if err != nil {
			s.B().Fail()
		}
	}
}

func (s *BenchDbOperations) BenchmarkPqSelectUsernameQueryRow() {
	var idn account.Identity
	s.B().ResetTimer()
	s.B().ReportAllocs()
	for n := 0; n < s.B().N; n++ {
		err := s.dbPq.QueryRow("SELECT username FROM identities WHERE id=$1", s.identity.ID.String()).Scan(&idn.Username)
		if err != nil {
			s.B().Fail()
		}
	}
}

func (s *BenchDbOperations) BenchmarkGormSelectIdentityFirst() {
	var idn Identity
	s.B().ResetTimer()
	s.B().ReportAllocs()
	for n := 0; n < s.B().N; n++ {
		db := s.DB.Select("username")
		db.Where("id=?", s.identity.ID.String()).First(&idn)
	}
}

func (s *BenchDbOperations) BenchmarkGormSelectIdentityFind() {
	var idn Identity
	s.B().ResetTimer()
	s.B().ReportAllocs()
	for n := 0; n < s.B().N; n++ {
		db := s.DB.Table("identities").Select("username")
		db.Where("id=?", s.identity.ID.String()).Find(&idn)
	}
}

func (s *BenchDbOperations) BenchmarkGormSelectIdentityRaw() {
	s.B().ResetTimer()
	s.B().ReportAllocs()

	todo := func() {
		var idns []account.Identity
		result, err := s.DB.Raw("select username from identities where id=?", s.identity.ID.String()).Rows()
		if err != nil {
			s.B().Fail()
		}
		defer result.Close()
		for result.Next() {
			var idn account.Identity
			result.Scan(
				&idn.Username)
			idns = append(idns, idn)
		}
	}
	for n := 0; n < s.B().N; n++ {
		todo()
	}
}

func (s *BenchDbOperations) BenchmarkPqSelectIdentityPreparedStatement() {
	queryStmt, err := s.dbPq.Prepare("SELECT username FROM identities WHERE id=$1")
	if err != nil {
		s.B().Fail()
	}
	var idn account.Identity
	s.B().ResetTimer()
	s.B().ReportAllocs()
	for n := 0; n < s.B().N; n++ {
		err = queryStmt.QueryRow(s.identity.ID.String()).Scan(
			&idn.Username)
		if err != nil {
			s.B().Logf("%v", err)
			s.B().Fail()
		}
	}
}

func (s *BenchDbOperations) BenchmarkPqSelectIdentityQueryRow() {
	var idn account.Identity
	s.B().ResetTimer()
	s.B().ReportAllocs()
	for n := 0; n < s.B().N; n++ {
		err := s.dbPq.QueryRow("SELECT username FROM identiteis WHERE id=$1", s.identity.ID.String()).Scan(
			&idn.Username)
		if err != nil {
			s.B().Logf("%v", err)
			s.B().Fail()
		}
	}
}
