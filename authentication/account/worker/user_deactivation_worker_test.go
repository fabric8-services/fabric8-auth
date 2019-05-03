package worker_test

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/application"
	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/authentication/account/worker"
	ososervice "github.com/fabric8-services/fabric8-auth/authentication/subscription/service"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	accountservicemock "github.com/fabric8-services/fabric8-auth/test/generated/authentication/account/service"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	baseworker "github.com/fabric8-services/fabric8-auth/worker"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gopkg.in/h2non/gock.v1"
)

type UserDeactivationWorkerTest struct {
	gormtestsupport.DBTestSuite
}

func TestUserDeactivationWorker(t *testing.T) {
	suite.Run(t, &UserDeactivationWorkerTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *UserDeactivationWorkerTest) TestDeactivateUsers() {
	// given
	config := accountservicemock.NewUserServiceConfigurationMock(s.T())
	config.GetUserDeactivationFetchLimitFunc = func() int {
		return 100
	}
	config.GetUserDeactivationInactivityPeriodDaysFunc = func() time.Duration {
		return 30 * 24 * time.Hour // 31 days, ie, 7 days after notification
	}
	config.GetUserDeactivationInactivityPeriodDaysFunc = func() time.Duration {
		return 20 * 24 * time.Hour // 24 days
	}
	// yesterday := time.Now().Add(-1 * 24 * time.Hour)
	ago40days := time.Now().Add(-40 * 24 * time.Hour) // 40 days since last activity and notified...
	ago30days := time.Now().Add(-30 * 24 * time.Hour) // 30 days since last activity and notified...

	app := gormapplication.NewGormDB(s.DB, s.Configuration, s.Wrappers)
	// also, use gock to intercep calls to other services
	defer gock.OffAll()

	s.Run("one user to deactivate once", func() {
		// given
		ctx, _, _ := testtoken.ContextWithTokenAndRequestID(s.T())
		userToDeactivate := s.Graph.CreateUser()
		userToDeactivate.User().Cluster = "TestCluster" // need to use the same clus
		err := s.Application.Users().Save(ctx, userToDeactivate.User())
		require.NoError(s.T(), err)
		identityToDeactivate := *userToDeactivate.Identity()
		identityToDeactivate.LastActive = &ago40days
		identityToDeactivate.DeactivationNotification = &ago30days
		err = s.Application.Identities().Save(ctx, &identityToDeactivate)
		require.NoError(s.T(), err)
		mockRemoteCalls(userToDeactivate.User(), identityToDeactivate, s.Configuration)
		// start the worker with a 50ms ticker
		w := s.newUserDeactivationWorker(ctx, "pod-a", app)
		freq := time.Millisecond * 50
		w.Start(freq)
		// wait a few cycles before checking the results
		time.Sleep(freq * 2)
		w.Stop()
		time.Sleep(freq * 10) // give workers some time to stop for good
		// verify that the lock was released
		l, err := s.Application.WorkerLockRepository().AcquireLock(context.Background(), "assert", worker.UserDeactivation)
		require.NoError(s.T(), err)
		err = l.Close()
		require.NoError(s.T(), err)
	})

	s.Run("multiple workers but only one working", func() {
		// given
		ctx, _, _ := testtoken.ContextWithTokenAndRequestID(s.T())
		userToDeactivate := s.Graph.CreateUser()
		userToDeactivate.User().Cluster = "TestCluster" // need to use the same clus
		err := s.Application.Users().Save(ctx, userToDeactivate.User())
		require.NoError(s.T(), err)
		identityToDeactivate := *userToDeactivate.Identity()
		identityToDeactivate.LastActive = &ago40days
		identityToDeactivate.DeactivationNotification = &ago30days
		err = s.Application.Identities().Save(ctx, &identityToDeactivate)
		require.NoError(s.T(), err)
		mockRemoteCalls(userToDeactivate.User(), identityToDeactivate, s.Configuration)
		// start the workers with a 50ms ticker
		freq := time.Millisecond * 50
		latch := sync.WaitGroup{}
		latch.Add(1)
		workers := []worker.UserDeactivationNotificationWorker{}
		for i := 1; i <= 2; i++ {
			fmt.Printf("initializing worker %d...\n", i)
			w := s.newUserDeactivationWorker(context.Background(), fmt.Sprintf("pod-%d", i), app)
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
		// verify that the lock was released
		l, err := s.Application.WorkerLockRepository().AcquireLock(context.Background(), "assert", worker.UserDeactivation)
		require.NoError(s.T(), err)
		err = l.Close()
		require.NoError(s.T(), err)
	})
}

func (s *UserDeactivationWorkerTest) newUserDeactivationWorker(ctx context.Context, podname string, app application.Application) worker.UserDeactivationWorker {
	err := os.Setenv("AUTH_POD_NAME", podname)
	require.NoError(s.T(), err)
	config, err := configuration.GetConfigurationData()
	require.NoError(s.T(), err)
	require.Equal(s.T(), podname, config.GetPodName())
	ctx = context.WithValue(ctx, baseworker.LockOwner, podname)
	return worker.NewUserDeactivationWorker(ctx, app)
}

func mockRemoteCalls(userToDeactivate *account.User, identity account.Identity, config ososervice.OSOSubscriptionServiceConfiguration) {
	fmt.Printf("Preparing Gock for user '%s' / identity id '%s' username '%s' \n", userToDeactivate.ID.String(), identity.ID.String(), identity.Username)
	// call to Cluster Service
	gock.Observe(gock.DumpRequest)
	// call to OSO Reg App
	gock.New(config.GetOSORegistrationAppURL()).
		Post(fmt.Sprintf("/api/accounts/%s/deprovision_osio", identity.Username)).
		MatchParam("authorization_username", config.GetOSORegistrationAppAdminUsername()).
		// not checking token here. Refer to OSO Reg App Deactivation tests
		Reply(200)
}
