package worker_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jinzhu/gorm"

	"github.com/fabric8-services/fabric8-auth/application"
	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/authentication/account/worker"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	accountservicemock "github.com/fabric8-services/fabric8-auth/test/generated/authentication/account/service"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	baseworker "github.com/fabric8-services/fabric8-auth/worker"

	"github.com/stretchr/testify/assert"
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
		identityToDeactivate := userToDeactivate.Identity()
		identityToDeactivate.LastActive = &ago40days
		identityToDeactivate.DeactivationNotification = &ago30days
		err = s.Application.Identities().Save(ctx, identityToDeactivate)
		require.NoError(s.T(), err)
		mockRemoteCalls(userToDeactivate.User(), identityToDeactivate)
		// start the worker with a 50ms ticker
		w := s.newUserDeactivationWorker(ctx, "pod-a", app)
		freq := time.Millisecond * 50
		w.Start(freq)
		// wait a few cycles before checking the results
		time.Sleep(freq * 2)
		w.Stop()
		time.Sleep(freq * 10) // give workers some time to stop for good
		// then load the user and check her deactivation notification status
		unscoped := func(db *gorm.DB) *gorm.DB {
			return db.Unscoped()
		}
		result, err := s.Application.Identities().Load(ctx, identityToDeactivate.ID, unscoped)
		require.NoError(s.T(), err)
		assert.NotNil(s.T(), result.DeletedAt)
	})

	s.Run("multiple workers but only one working", func() {
		// given
		ctx, _, _ := testtoken.ContextWithTokenAndRequestID(s.T())
		userToDeactivate := s.Graph.CreateUser()
		userToDeactivate.User().Cluster = "TestCluster" // need to use the same clus
		err := s.Application.Users().Save(ctx, userToDeactivate.User())
		require.NoError(s.T(), err)
		identityToDeactivate := userToDeactivate.Identity()
		identityToDeactivate.LastActive = &ago40days
		identityToDeactivate.DeactivationNotification = &ago30days
		err = s.Application.Identities().Save(ctx, identityToDeactivate)
		require.NoError(s.T(), err)
		mockRemoteCalls(userToDeactivate.User(), identityToDeactivate)
		// start the workers with a 50ms ticker
		w1 := s.newUserDeactivationWorker(ctx, "pod-1", app)
		w2 := s.newUserDeactivationWorker(ctx, "pod-2", app)
		w3 := s.newUserDeactivationWorker(ctx, "pod-3", app)
		w4 := s.newUserDeactivationWorker(ctx, "pod-4", app)
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
		time.Sleep(freq * 5) // give workers some time to stop for good
		// then load the user and check her deactivation notification status
		unscoped := func(db *gorm.DB) *gorm.DB {
			return db.Unscoped()
		}
		result, err := s.Application.Identities().Load(ctx, identityToDeactivate.ID, unscoped)
		require.NoError(s.T(), err)
		assert.NotNil(s.T(), result.DeletedAt)
		// verify that the lock was released
		l, err := s.Application.WorkerLockRepository().AcquireLock(context.Background(), "assert", worker.UserDeactivation)
		require.NoError(s.T(), err)
		l.Close()
	})
}

func (s *UserDeactivationWorkerTest) newUserDeactivationWorker(ctx context.Context, podname string, app application.Application) worker.UserDeactivationWorker {
	os.Setenv("AUTH_POD_NAME", podname)
	config, err := configuration.GetConfigurationData()
	require.NoError(s.T(), err)
	require.Equal(s.T(), podname, config.GetPodName())
	ctx = context.WithValue(ctx, baseworker.LockOwner, podname)
	return worker.NewUserDeactivationWorker(ctx, app)
}

func mockRemoteCalls(userToDeactivate *account.User, identity *account.Identity) {
	fmt.Printf("Preparing Gock for user '%s' / identity '%s'\n", userToDeactivate.ID.String(), identity.ID.String())
	// call to Cluster Service
	gock.Observe(gock.DumpRequest)
	gock.New("http://f8cluster").
		Get("/api/clusters/auth").
		Reply(200).
		BodyString(
			fmt.Sprintf(`{
					"data": [
						{
							"token-provider-id": "33456e01-0ce4-4da2-b94d-daa968412662",
							"api-url": "%s",
							"app-dns": "a347.foo.openshiftapps.com",
							"auth-client-default-scope": "user:full",
							"auth-client-id": "openshift-io",
							"auth-client-secret": "067da2df-b721-48cd-8e76-ac26e9140218",
							"capacity-exhausted": false,
							"console-url": "https://console.foo.openshift.com/console/",
							"logging-url": "https://console.foo.openshift.com/console/",
							"metrics-url": "https://metrics.foo.openshift.com/",
							"name": "foo",
							"service-account-token": "1d147ba1-2832-4048-b1c5-21ae37377f0d",
							"service-account-username": "devtools-sre"
						}
					]
				}`, userToDeactivate.Cluster))
	// call to WIT Service
	gock.New("http://localhost:8080").
		Delete(fmt.Sprintf("/api/users/username/%s", identity.ID.String())).
		Reply(200)
	// call to Tenant Service
	gock.New("http://localhost:8090").
		Delete(fmt.Sprintf("/api/tenants/%s", identity.ID.String())).
		Reply(204)
}