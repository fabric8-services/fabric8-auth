package worker_test

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/authentication/provider/repository"
	"github.com/fabric8-services/fabric8-auth/authentication/provider/worker"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	baseworker "github.com/fabric8-services/fabric8-auth/worker"

	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type OAuthStateReferenceCleanupWorkerTest struct {
	gormtestsupport.DBTestSuite
}

func TestOAuthStateReferenceCleanupWorker(t *testing.T) {
	suite.Run(t, &OAuthStateReferenceCleanupWorkerTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *OAuthStateReferenceCleanupWorkerTest) TestCleanup() {
	// given
	ago40days := time.Now().Add(-40 * 24 * time.Hour) // 40 days ago

	app := gormapplication.NewGormDB(s.DB, s.Configuration, s.Wrappers)

	s.Run("one state reference to cleanup", func() {
		// given 2 OAuth state references
		state := &repository.OauthStateReference{
			Lifecycle: gormsupport.Lifecycle{
				CreatedAt: ago40days, // 40 days ago
			},
			State:    uuid.NewV4().String(),
			Referrer: "domain.org",
		}
		_, err := s.Application.OauthStates().Create(s.Ctx, state)
		require.Nil(s.T(), err, "Could not create state reference")
		state2 := &repository.OauthStateReference{
			State:    uuid.NewV4().String(),
			Referrer: "anotherdomain.com",
		}
		_, err = s.Application.OauthStates().Create(s.Ctx, state2)
		require.Nil(s.T(), err, "Could not create state reference")

		// start the worker with a 50ms ticker
		w := s.newOAuthStateReferenceCleanupWorker(context.Background(), "pod-a", app)
		freq := time.Millisecond * 50
		w.Start(freq)
		// wait a few cycles before checking the results
		time.Sleep(freq * 2)
		// now stop all workers
		stop(w)
		// verify that the lock was released
		l, err := s.Application.WorkerLockRepository().AcquireLock(context.Background(), "assert", worker.OAuthStateReferenceCleanup)
		require.NoError(s.T(), err)
		err = l.Close()
		require.NoError(s.T(), err)
		//
	})

	s.Run("multiple workers and only one active", func() {
		// given 2 OAuth state references
		state := &repository.OauthStateReference{
			Lifecycle: gormsupport.Lifecycle{
				CreatedAt: ago40days, // 40 days ago
			},
			State:    uuid.NewV4().String(),
			Referrer: "domain.org",
		}
		_, err := s.Application.OauthStates().Create(s.Ctx, state)
		require.Nil(s.T(), err, "Could not create state reference")
		state2 := &repository.OauthStateReference{
			State:    uuid.NewV4().String(),
			Referrer: "anotherdomain.com",
		}
		_, err = s.Application.OauthStates().Create(s.Ctx, state2)
		require.Nil(s.T(), err, "Could not create state reference")

		// start the workers with a 50ms ticker
		freq := time.Millisecond * 50
		latch := sync.WaitGroup{}
		latch.Add(1)
		workers := []baseworker.Worker{}
		for i := 1; i <= 2; i++ {
			fmt.Printf("initializing worker %d...\n", i)
			w := s.newOAuthStateReferenceCleanupWorker(context.Background(), fmt.Sprintf("pod-%d", i), app)
			workers = append(workers, w)
			go func(i int) {
				// now, wait for latch to be released so that all workers start at the same time
				fmt.Printf("worker %d now waiting to latch to start...\n", i)
				latch.Wait()
				w.Start(freq)
			}(i)
		}
		latch.Done()
		// wait a few cycles before checking the results
		time.Sleep(freq * 5)
		// now stop all workers
		stop(workers...)
		// verify that the lock was released
		l, err := s.Application.WorkerLockRepository().AcquireLock(context.Background(), "assert", worker.OAuthStateReferenceCleanup)
		require.NoError(s.T(), err)
		err = l.Close()
		require.NoError(s.T(), err)
	})

}

func (s *OAuthStateReferenceCleanupWorkerTest) newOAuthStateReferenceCleanupWorker(ctx context.Context, podname string, app application.Application) baseworker.Worker {
	err := os.Setenv("AUTH_POD_NAME", podname)
	require.NoError(s.T(), err)
	config, err := configuration.GetConfigurationData()
	require.NoError(s.T(), err)
	require.Equal(s.T(), podname, config.GetPodName())
	ctx = context.WithValue(ctx, baseworker.LockOwner, podname)
	return worker.NewOAuthStateReferenceCleanupWorker(ctx, app)
}

func (s *OAuthStateReferenceCleanupWorkerTest) verifyCleanup(state string) {
	ref, err := s.Application.OauthStates().Load(context.Background(), state)
	assert.Error(s.T(), err) // not found as state.delete_at is set
	assert.Nil(s.T(), ref)
}

// stop stops the given workers and waits until they all actually stopped before returning.
func stop(workers ...baseworker.Worker) {
	freq := time.Millisecond * 50
	// now stop all workers
	stopWG := sync.WaitGroup{}
	for _, w := range workers {
		stopWG.Add(1)
		go func(w baseworker.Worker) {
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
