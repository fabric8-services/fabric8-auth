package worker_test

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/application/service/factory"
	"github.com/fabric8-services/fabric8-auth/authentication/account/worker"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/notification"
	"github.com/fabric8-services/fabric8-auth/rest"
	appservicemock "github.com/fabric8-services/fabric8-auth/test/generated/application/service"
	accountservicemock "github.com/fabric8-services/fabric8-auth/test/generated/authentication/account/service"
	baseworker "github.com/fabric8-services/fabric8-auth/worker"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type UserDeactivationNotificationWorkerTest struct {
	gormtestsupport.DBTestSuite
}

func TestUserDeactivationNotificationWorker(t *testing.T) {
	suite.Run(t, &UserDeactivationNotificationWorkerTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *UserDeactivationNotificationWorkerTest) TestNotifyUsers() {
	// given
	config := accountservicemock.NewUserServiceConfigurationMock(s.T())
	config.GetUserDeactivationFetchLimitFunc = func() int {
		return 100
	}
	config.GetUserDeactivationInactivityPeriodFunc = func() time.Duration {
		return 30 * 24 * time.Hour // 31 days, ie, 7 days after notification
	}
	config.GetUserDeactivationInactivityNotificationPeriodFunc = func() time.Duration {
		return 20 * 24 * time.Hour // 24 days
	}
	config.GetPostDeactivationNotificationDelayFunc = func() time.Duration {
		return 5 * time.Millisecond
	}
	ctx := context.Background()
	// yesterday := time.Now().Add(-1 * 24 * time.Hour)
	ago40days := time.Now().Add(-40 * 24 * time.Hour) // 40 days since last activity and notified...

	var notificationServiceMock *appservicemock.NotificationServiceMock
	var app application.Application
	s.SetupSubtest = func() {
		notificationServiceMock = appservicemock.NewNotificationServiceMock(s.T())
		notificationServiceMock.SendMessageAsyncFunc = func(ctx context.Context, msg notification.Message, options ...rest.HTTPClientOption) (r chan error, r1 error) {
			return nil, nil
		}
		app = gormapplication.NewGormDB(s.DB, s.Configuration, s.Wrappers, factory.WithNotificationService(notificationServiceMock))
	}

	s.Run("one user to notify once", func() {
		// given
		user1 := s.Graph.CreateUser().User()
		identity1 := user1.Identities[0]
		identity1.LastActive = &ago40days
		err := s.Application.Identities().Save(ctx, &identity1)
		require.NoError(s.T(), err)
		// start the worker with a 50ms ticker
		w := s.newUserDeactivationNotificationWorker(context.Background(), "pod-a", app)
		freq := time.Millisecond * 50
		w.Start(freq)
		// wait a few cycles before checking the results
		time.Sleep(freq * 5)
		w.Stop()
		time.Sleep(freq * 10) // give workers some time to stop for good
		// then load the user and check her deactivation notification status
		result, err := s.Application.Identities().Load(context.Background(), identity1.ID)
		require.NoError(s.T(), err)
		assert.NotNil(s.T(), result.DeactivationNotification)
		// notification only sent once to the user
		assert.Equal(s.T(), uint64(1), notificationServiceMock.SendMessageAsyncCounter)
	})

	s.Run("multiple workers but only one working", func() {
		// given
		user1 := s.Graph.CreateUser().User()
		identity1 := user1.Identities[0]
		identity1.LastActive = &ago40days
		err := s.Application.Identities().Save(ctx, &identity1)
		require.NoError(s.T(), err)
		// start the workers with a 50ms ticker
		freq := time.Millisecond * 50
		latch := sync.WaitGroup{}
		latch.Add(1)
		workers := []worker.UserDeactivationNotificationWorker{}
		for i := 1; i <= 5; i++ {
			fmt.Printf("initializing worker %d...\n", i)
			w := s.newUserDeactivationNotificationWorker(context.Background(), fmt.Sprintf("pod-%d", i), app)
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
		for _, w := range workers {
			w.Stop()
		}
		time.Sleep(freq * 10) // give workers some time to stop for good
		// then load the user and check her deactivation notification status
		result, err := s.Application.Identities().Load(context.Background(), identity1.ID)
		require.NoError(s.T(), err)
		assert.NotNil(s.T(), result.DeactivationNotification)
		// notification only sent once to the user
		assert.Equal(s.T(), uint64(1), notificationServiceMock.SendMessageAsyncCounter)
		// verify that the lock was released
		l, err := s.Application.WorkerLockRepository().AcquireLock(context.Background(), "assert", worker.UserDeactivationNotification)
		require.NoError(s.T(), err)
		err = l.Close()
		require.NoError(s.T(), err)
	})
}

func (s *UserDeactivationNotificationWorkerTest) newUserDeactivationNotificationWorker(ctx context.Context, podname string, app application.Application) worker.UserDeactivationNotificationWorker {
	err := os.Setenv("AUTH_POD_NAME", podname)
	require.NoError(s.T(), err)
	config, err := configuration.GetConfigurationData()
	require.NoError(s.T(), err)
	require.Equal(s.T(), podname, config.GetPodName())
	ctx = context.WithValue(ctx, baseworker.LockOwner, podname)
	return worker.NewUserDeactivationNotificationWorker(ctx, app)
}
