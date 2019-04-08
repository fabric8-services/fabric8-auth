package worker_test

import (
	"context"
	"os"
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
	config.GetUserDeactivationInactivityPeriodDaysFunc = func() time.Duration {
		return 30 * 24 * time.Hour // 31 days, ie, 7 days after notification
	}
	config.GetUserDeactivationInactivityNotificationPeriodDaysFunc = func() time.Duration {
		return 20 * 24 * time.Hour // 24 days
	}
	config.GetPostDeactivationNotificationDelayMillisFunc = func() time.Duration {
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
		w1 := s.newUserDeactivationNotificationWorker(context.Background(), "pod-1", app)
		w2 := s.newUserDeactivationNotificationWorker(context.Background(), "pod-2", app)
		w3 := s.newUserDeactivationNotificationWorker(context.Background(), "pod-3", app)
		w4 := s.newUserDeactivationNotificationWorker(context.Background(), "pod-4", app)
		freq := time.Millisecond * 50
		w1.Start(freq)
		w2.Start(freq)
		w3.Start(freq)
		w4.Start(freq)
		// wait a few cycles before checking the results
		time.Sleep(freq * 5)
		w1.Stop()
		w2.Stop()
		w3.Stop()
		w4.Stop()
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
		l.Close()
	})
}

func (s *UserDeactivationNotificationWorkerTest) newUserDeactivationNotificationWorker(ctx context.Context, podname string, app application.Application) worker.UserDeactivationNotificationWorker {
	os.Setenv("AUTH_POD_NAME", podname)
	config, err := configuration.GetConfigurationData()
	require.NoError(s.T(), err)
	require.Equal(s.T(), podname, config.GetPodName())
	ctx = context.WithValue(ctx, baseworker.LockOwner, podname)
	return worker.NewUserDeactivationNotificationWorker(ctx, app)
}
