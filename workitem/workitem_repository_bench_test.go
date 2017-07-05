package workitem_test

import (
	"testing"

	"golang.org/x/net/context"

	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/criteria"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormsupport/cleaner"
	gormbench "github.com/fabric8-services/fabric8-auth/gormtestsupport/benchmark"
	"github.com/fabric8-services/fabric8-auth/migration"
	"github.com/fabric8-services/fabric8-auth/space"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	"github.com/fabric8-services/fabric8-auth/workitem"

	uuid "github.com/satori/go.uuid"
)

type BenchWorkItemRepository struct {
	gormbench.DBBenchSuite
	clean     func()
	repo      workitem.WorkItemRepository
	ctx       context.Context
	creatorID uuid.UUID
}

func BenchmarkRunWorkItemRepository(b *testing.B) {
	testsupport.Run(b, &BenchWorkItemRepository{DBBenchSuite: gormbench.NewDBBenchSuite("../config.yaml")})
}

func (s *BenchWorkItemRepository) SetupSuite() {
	s.DBBenchSuite.SetupSuite()
	s.ctx = migration.NewMigrationContext(context.Background())
	s.DBBenchSuite.PopulateDBBenchSuite(s.ctx)
}

func (s *BenchWorkItemRepository) SetupBenchmark() {
	s.clean = cleaner.DeleteCreatedEntities(s.DB)
	s.repo = workitem.NewWorkItemRepository(s.DB)
	testIdentity, err := testsupport.CreateTestIdentity(s.DB, "jdoe", "test")
	if err != nil {
		s.B().Fail()
	}
	s.creatorID = testIdentity.ID
}

func (s *BenchWorkItemRepository) TearDownBenchmark() {
	s.clean()
}

func (r *BenchWorkItemRepository) BenchmarkLoadWorkItem() {
	wi, err := r.repo.Create(
		r.ctx, space.SystemSpace, workitem.SystemBug,
		map[string]interface{}{
			workitem.SystemTitle: "Title",
			workitem.SystemState: workitem.SystemStateNew,
		}, r.creatorID)
	if err != nil {
		r.B().Fail()
	}

	r.B().ResetTimer()
	r.B().ReportAllocs()
	for n := 0; n < r.B().N; n++ {
		if s, err := r.repo.LoadByID(context.Background(), wi.ID); err != nil || (err == nil && s == nil) {
			r.B().Fail()
		}
	}
}

func (r *BenchWorkItemRepository) BenchmarkListWorkItems() {
	r.B().ResetTimer()
	r.B().ReportAllocs()
	for n := 0; n < r.B().N; n++ {
		if s, _, err := r.repo.List(context.Background(), space.SystemSpace, criteria.Literal(true), nil, nil, nil); err != nil || (err == nil && s == nil) {
			r.B().Fail()
		}
	}
}

func (r *BenchWorkItemRepository) BenchmarkListWorkItemsTransaction() {
	r.B().ResetTimer()
	r.B().ReportAllocs()
	for n := 0; n < r.B().N; n++ {
		if err := application.Transactional(gormapplication.NewGormDB(r.DB), func(app application.Application) error {
			_, _, err := r.repo.List(context.Background(), space.SystemSpace, criteria.Literal(true), nil, nil, nil)
			return err
		}); err != nil {
			r.B().Fail()
		}
	}
}
