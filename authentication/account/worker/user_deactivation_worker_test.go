package worker_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/fabric8-services/fabric8-auth/application/service/factory"

	"github.com/fabric8-services/fabric8-auth/application"
	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	userservice "github.com/fabric8-services/fabric8-auth/authentication/account/service"
	"github.com/fabric8-services/fabric8-auth/authentication/account/worker"
	ososervice "github.com/fabric8-services/fabric8-auth/authentication/subscription/service"
	cheservice "github.com/fabric8-services/fabric8-auth/che/service"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	accountservicemock "github.com/fabric8-services/fabric8-auth/test/generated/authentication/account/service"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	baseworker "github.com/fabric8-services/fabric8-auth/worker"

	uuid "github.com/satori/go.uuid"
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
	config.GetUserDeactivationInactivityPeriodFunc = func() time.Duration {
		return 30 * 24 * time.Hour // 31 days, ie, 7 days after notification
	}
	config.GetUserDeactivationInactivityNotificationPeriodFunc = func() time.Duration {
		return 20 * 24 * time.Hour // 24 days
	}
	config.GetUserDeactivationWhiteListFunc = func() (empty []string) {
		return empty
	}
	config.GetUserDeactivationRescheduleDelayFunc = func() time.Duration {
		return 10 * 24 * time.Hour
	}

	// yesterday := time.Now().Add(-1 * 24 * time.Hour)
	ago40days := time.Now().Add(-40 * 24 * time.Hour) // 40 days since last activity and notified...
	ago30days := time.Now().Add(-30 * 24 * time.Hour) // 30 days since last activity and notified...

	srvCtx := factory.NewServiceContext(s.Application, s.Application, s.Configuration, s.Wrappers)
	userSrv := userservice.NewUserService(srvCtx, config)
	app := gormapplication.NewGormDB(s.DB, s.Configuration, s.Wrappers, factory.WithUserService(userSrv))
	// also, use gock to intercep calls to other services
	defer gock.Off()

	s.Run("one user to deactivate once", func() {
		// given
		ctx, _, _ := testtoken.ContextWithTokenAndRequestID(s.T())
		userToDeactivate := s.Graph.CreateUser()
		userToDeactivate.User().Cluster = "starter-us-east-2a"
		err := s.Application.Users().Save(ctx, userToDeactivate.User())
		require.NoError(s.T(), err)
		identityToDeactivate := *userToDeactivate.Identity()
		identityToDeactivate.LastActive = &ago40days
		identityToDeactivate.DeactivationNotification = &ago30days
		now := time.Now()
		identityToDeactivate.DeactivationScheduled = &now
		err = s.Application.Identities().Save(ctx, &identityToDeactivate)
		require.NoError(s.T(), err)
		mockRemoteCalls(userToDeactivate.User(), identityToDeactivate, s.Configuration, 200)
		// start the worker with a 50ms ticker
		w := s.newUserDeactivationWorker(ctx, "pod-a", app)
		freq := time.Millisecond * 50
		w.Start(freq)
		// wait a few cycles before checking the results
		time.Sleep(freq * 2)
		// now stop all workers
		stop(w)
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
		userToDeactivate.User().Cluster = "starter-us-east-2a"
		err := s.Application.Users().Save(ctx, userToDeactivate.User())
		require.NoError(s.T(), err)
		identityToDeactivate := *userToDeactivate.Identity()
		identityToDeactivate.LastActive = &ago40days
		identityToDeactivate.DeactivationNotification = &ago30days
		now := time.Now()
		identityToDeactivate.DeactivationScheduled = &now
		err = s.Application.Identities().Save(ctx, &identityToDeactivate)
		require.NoError(s.T(), err)
		mockRemoteCalls(userToDeactivate.User(), identityToDeactivate, s.Configuration, 200)
		// start the workers with a 50ms ticker
		freq := time.Millisecond * 50
		latch := sync.WaitGroup{}
		latch.Add(1)
		workers := []baseworker.Worker{}
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
		stop(workers...)
		// verify that the lock was released
		l, err := s.Application.WorkerLockRepository().AcquireLock(context.Background(), "assert", worker.UserDeactivation)
		require.NoError(s.T(), err)
		err = l.Close()
		require.NoError(s.T(), err)
	})

	s.Run("user not found in reg app", func() {
		// given
		ctx, _, _ := testtoken.ContextWithTokenAndRequestID(s.T())
		userToDeactivate := s.Graph.CreateUser()
		userToDeactivate.User().Cluster = "starter-us-east-2a"
		err := s.Application.Users().Save(ctx, userToDeactivate.User())
		require.NoError(s.T(), err)
		identityToDeactivate := *userToDeactivate.Identity()
		identityToDeactivate.LastActive = &ago40days
		identityToDeactivate.DeactivationNotification = &ago30days
		now := time.Now()
		identityToDeactivate.DeactivationScheduled = &now
		err = s.Application.Identities().Save(ctx, &identityToDeactivate)
		require.NoError(s.T(), err)
		mockRemoteCalls(userToDeactivate.User(), identityToDeactivate, s.Configuration, 404)
		mockCheCalls(s.Configuration)
		mockTenantCalls(s.Configuration)
		mockClusterCalls(s.Configuration)
		mockAdminConsoleCalls(s.Configuration)
		// start the worker with a 50ms ticker
		w := s.newUserDeactivationWorker(ctx, "pod-a", app)
		freq := time.Millisecond * 50
		w.Start(freq)
		// wait a few cycles before checking the results
		time.Sleep(freq * 2)
		// now stop all workers
		stop(w)
		// verify that the lock was released
		l, err := s.Application.WorkerLockRepository().AcquireLock(context.Background(), "assert", worker.UserDeactivation)
		require.NoError(s.T(), err)
		err = l.Close()
		require.NoError(s.T(), err)
		s.verifyDeactivate(userToDeactivate.User().ID)
	})
}

func (s *UserDeactivationWorkerTest) newUserDeactivationWorker(ctx context.Context, podname string, app application.Application) baseworker.Worker {
	err := os.Setenv("AUTH_POD_NAME", podname)
	require.NoError(s.T(), err)
	config, err := configuration.GetConfigurationData()
	require.NoError(s.T(), err)
	require.Equal(s.T(), podname, config.GetPodName())
	ctx = context.WithValue(ctx, baseworker.LockOwner, podname)
	return worker.NewUserDeactivationWorker(ctx, app)
}

func (s *UserDeactivationWorkerTest) verifyDeactivate(id uuid.UUID) {
	user, err := s.Application.Users().Load(context.Background(), id)
	assert.Error(s.T(), err) // not found as users.delete_at is set
	assert.Nil(s.T(), user)
}

func mockRemoteCalls(userToDeactivate *account.User, identity account.Identity, config ososervice.OSOSubscriptionServiceConfiguration, resStatus int) {
	fmt.Printf("Preparing Gock for user '%s' / identity id '%s' username '%s' \n", userToDeactivate.ID.String(), identity.ID.String(), identity.Username)
	// call to Cluster Service
	gock.Observe(gock.DumpRequest)
	// call to OSO Reg App
	gock.New(config.GetOSORegistrationAppURL()).
		Post(fmt.Sprintf("/api/accounts/%s/deprovision_osio", identity.Username)).
		MatchParam("authorization_username", config.GetOSORegistrationAppAdminUsername()).
		// not checking token here. Refer to OSO Reg App Deactivation tests
		Reply(resStatus)
}

func mockCheCalls(config cheservice.Configuration) {
	gock.New(config.GetCheServiceURL()).Reply(http.StatusNoContent)
}

func mockTenantCalls(config *configuration.ConfigurationData) {
	gock.New(config.GetTenantServiceURL()).Reply(http.StatusNoContent)
}

func mockClusterCalls(config *configuration.ConfigurationData) {
	gock.New(config.GetClusterServiceURL()).Reply(http.StatusOK).BodyString(`{
		"data": [
			{
				"api-url": "starter-us-east-2a",
				"app-dns": "b542.starter-us-east-2a.openshiftapps.com",
				"auth-client-default-scope": "user:full",
				"auth-client-id": "openshift-io",
				"auth-client-secret": "26c8c584-cbac-427d-8330-8b430b6ec620",
				"capacity-exhausted": false,
				"name": "starter-us-east-2a",
				"service-account-token": "eef1c5b8-f1f4-45dd-beef-7c34be5d9f9b",
				"service-account-username": "devtools-sre",
				"token-provider-id": "dd0ee660-3549-4617-9cab-6e679aab41e9"
			}
		]
	}`)
}

func mockAdminConsoleCalls(config *configuration.ConfigurationData) {
	gock.New(config.GetAdminConsoleServiceURL()).Reply(http.StatusOK)
}
