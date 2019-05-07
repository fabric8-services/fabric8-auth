package worker_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	gormtestsupport "github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/migration"
	"github.com/fabric8-services/fabric8-auth/worker"

	"cirello.io/pglock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type WorkerTestSuite struct {
	gormtestsupport.DBTestSuite
	application application.Application
	ctx         context.Context
}

func TestWorker(t *testing.T) {
	suite.Run(t, &WorkerTestSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

// SetupSuite overrides the DBTestSuite's function but calls it before doing anything else
// The SetupSuite method will run before the tests in the suite are run.
// It sets up a database connection for all the tests in this suite without polluting global space.
func (s *WorkerTestSuite) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	s.ctx = migration.NewMigrationContext(context.Background())
	s.application = gormapplication.NewGormDB(s.DB, s.Configuration, nil)
}

func (s *WorkerTestSuite) TestMultipleWorkers() {
	// run this test multiple times
	for i := 0; i < 5; i++ {
		s.testMultipleWorkers()
	}
}

func (s *WorkerTestSuite) testMultipleWorkers() {
	// start the workers with a 50ms ticker
	freq := time.Millisecond * 50
	latch := sync.WaitGroup{}
	latch.Add(1)
	workers := []worker.Worker{}
	doers := []*doer{}
	for i := 0; i < 3; i++ {
		w := &worker.BaseWorker{
			Ctx:   s.ctx,
			App:   s.application,
			Owner: fmt.Sprintf("test-worker-%d", i),
			Name:  "test-worker",
			Opts: []pglock.ClientOption{
				pglock.WithCustomTable("worker_lock"),
				pglock.WithLeaseDuration(freq * 2),
				pglock.WithHeartbeatFrequency(freq),
				pglock.WithLogger(log.Logger()),
			},
		}

		doer := &doer{freq: freq, owner: w.Owner}
		w.Do = doer.do
		doers = append(doers, doer)

		workers = append(workers, w)
		go func(i int) {
			// now, wait for latch to be released so that all workers start at the same time
			latch.Wait()
			w.Start(freq)
		}(i)
	}
	latch.Done()
	// wait a few cycles before checking the results
	time.Sleep(freq * 10)
	// check that the lock has been acquired
	_, err := s.application.WorkerLockRepository().GetLock(s.ctx, "test-worker")
	require.NoError(s.T(), err)
	// check that the only one doer did all the work
	var doersCount int
	for _, doer := range doers {
		if doer.count > 0 {
			doersCount++
		}
	}
	assert.Equal(s.T(), 1, doersCount, "only one doer was expected to be called")
	// stop all workers
	stop(workers...)
	// verify that the lock has been released
	_, err = s.application.WorkerLockRepository().GetLock(s.ctx, "test-worker")
	require.Error(s.T(), err)
	require.Equal(s.T(), "cannot obtain the lock 'test-worker': not exists: lock not found", err.Error())
}

func stop(workers ...worker.Worker) {
	fmt.Printf("stopping %d workers...\n", len(workers))
	freq := time.Millisecond * 50
	// first, stop all workers that did not acquire the lock
	stopWG := sync.WaitGroup{}
	for _, w := range workers {
		stopWG.Add(1)
		go func(w worker.Worker) {
			w.Stop()
			for {
				time.Sleep(freq) // give workers some time to stop for good
				if w.IsStopped() {
					stopWG.Done()
					return // only exit when the worker is stopped
				}
			}
		}(w)
	}
	stopWG.Wait()
}

type doer struct {
	freq  time.Duration
	owner string
	count int
}

func (d *doer) do() {
	d.count++
	time.Sleep(d.freq * 2)
}
