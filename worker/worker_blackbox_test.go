package worker_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/worker"

	"cirello.io/pglock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type WorkerTestSuite struct {
	gormtestsupport.DBTestSuite
}

func TestWorker(t *testing.T) {
	suite.Run(t, &WorkerTestSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *WorkerTestSuite) TestMultipleWorkers() {
	// start the workers with a 50ms ticker
	freq := time.Millisecond * 50
	latch := sync.WaitGroup{}
	latch.Add(1)
	workers := []worker.Worker{}
	doers := []*doer{}
	for i := 0; i < 3; i++ {
		w := &worker.BaseWorker{
			Ctx:   s.Ctx,
			App:   s.Application,
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
	_, err := s.Application.WorkerLockRepository().GetLock(s.Ctx, "test-worker")
	require.NoError(s.T(), err)
	stop(workers...)
	// check that the only one doer did all the work
	var doersCount int
	for _, doer := range doers {
		if doer.count > 0 {
			doersCount++
		}
	}
	assert.Equal(s.T(), 1, doersCount, "only one doer was expected to be called")
	// verify that the lock has been deleted
	_, err = s.Application.WorkerLockRepository().GetLock(s.Ctx, "test-worker")
	require.Error(s.T(), err)
	require.Equal(s.T(), "cannot obtain the lock 'test-worker': not exists: lock not found", err.Error())
}

func stop(workers ...worker.Worker) {
	freq := time.Millisecond * 50
	// now stop all workers
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
