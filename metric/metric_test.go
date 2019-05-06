package metric_test

import (
	"context"
	"io/ioutil"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/application/service/factory"
	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	userservice "github.com/fabric8-services/fabric8-auth/authentication/account/service"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/metric"
	"github.com/fabric8-services/fabric8-auth/notification"
	"github.com/fabric8-services/fabric8-auth/rest"
	servicemock "github.com/fabric8-services/fabric8-auth/test/generated/application/service"
	userservicemock "github.com/fabric8-services/fabric8-auth/test/generated/authentication/account/service"
	testsuite "github.com/fabric8-services/fabric8-common/test/suite"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type MetricTestSuite struct {
	gormtestsupport.DBTestSuite
}

func TestMetric(t *testing.T) {
	suite.Run(t, &MetricTestSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

const (
	successful string = "true"
	failure    string = "false"
)

func (s *MetricTestSuite) TestUserDeactivationNotificationCounter() {

	ctx := context.Background()
	config := userservicemock.NewUserServiceConfigurationMock(s.T())
	config.GetUserDeactivationInactivityPeriodFunc = func() time.Duration {
		return 97 * 24 * time.Hour
	}
	config.GetPostDeactivationNotificationDelayFunc = func() time.Duration {
		return 5 * time.Millisecond
	}
	now := time.Now() // make sure we use the same 'now' everywhere in the test
	nowf := func() time.Time {
		return now
	}

	// configure the `SetupSubtest` and `TearDownSubtest` to setup/reset data after each subtest
	var identity1, identity2 account.Identity
	var user1, user2 account.User

	s.SetupSubtest = func() {
		s.CleanTest = testsuite.DeleteCreatedEntities(s.DB, s.Configuration)
		ago40days := time.Now().Add(-40 * 24 * time.Hour) // 40 days since last activity and notified...
		ago70days := time.Now().Add(-70 * 24 * time.Hour) // 70 days since last activity and notified...
		// user/identity1: 40 days since last activity and not notified
		user1 = *s.Graph.CreateUser().User()
		identity1 = user1.Identities[0]
		identity1.LastActive = &ago40days
		err := s.Application.Identities().Save(ctx, &identity1)
		require.NoError(s.T(), err)
		// user/identity2: 70 days since last activity and not notified
		user2 = *s.Graph.CreateUser().User()
		identity2 = user2.Identities[0]
		identity2.LastActive = &ago70days
		err = s.Application.Identities().Save(ctx, &identity2)
		require.NoError(s.T(), err)
		metric.RegisterMetrics()
	}

	s.TearDownSubtest = func() {
		err := s.CleanTest()
		require.NoError(s.T(), err)
		metric.UnregisterMetrics()
	}

	s.Run("one user to deactivate", func() {
		// given
		config.GetUserDeactivationFetchLimitFunc = func() int {
			return 100
		}
		config.GetUserDeactivationInactivityNotificationPeriodFunc = func() time.Duration {
			return 60 * 24 * time.Hour // 60 days
		}
		notificationServiceMock := servicemock.NewNotificationServiceMock(s.T())
		notificationServiceMock.SendMessageFunc = func(ctx context.Context, msg notification.Message, options ...rest.HTTPClientOption) error {
			return nil
		}
		userSvc := userservice.NewUserService(factory.NewServiceContext(s.Application, s.Application, nil, nil, factory.WithNotificationService(notificationServiceMock)), config)
		// when
		result, err := userSvc.NotifyIdentitiesBeforeDeactivation(ctx, nowf)
		// then
		require.NoError(s.T(), err)
		require.Len(s.T(), result, 1)
		// verify metrics
		s.verifyCount(metric.UserDeactivationNotificationCounter, 1, successful)
		s.verifyCount(metric.UserDeactivationNotificationCounter, 0, failure)
		s.verifyCount(metric.UserDeactivationCounter, 0, successful)
		s.verifyCount(metric.UserDeactivationCounter, 0, failure)
	})

	s.Run("two users to deactivate", func() {
		// given
		config.GetUserDeactivationFetchLimitFunc = func() int {
			return 100
		}
		config.GetUserDeactivationInactivityNotificationPeriodFunc = func() time.Duration {
			return 30 * 24 * time.Hour // 30 days
		}
		var msgToSend []notification.Message
		notificationServiceMock := servicemock.NewNotificationServiceMock(s.T())
		notificationServiceMock.SendMessageFunc = func(ctx context.Context, msg notification.Message, options ...rest.HTTPClientOption) error {
			msgToSend = append(msgToSend, msg)
			return nil
		}
		userSvc := userservice.NewUserService(factory.NewServiceContext(s.Application, s.Application, nil, nil, factory.WithNotificationService(notificationServiceMock)), config)
		// when
		result, err := userSvc.NotifyIdentitiesBeforeDeactivation(ctx, nowf)
		// then
		require.NoError(s.T(), err)
		require.Len(s.T(), result, 2)
		// verify metrics
		s.verifyCount(metric.UserDeactivationNotificationCounter, 2, successful)
		s.verifyCount(metric.UserDeactivationNotificationCounter, 0, failure)
		s.verifyCount(metric.UserDeactivationCounter, 0, successful)
		s.verifyCount(metric.UserDeactivationCounter, 0, failure)
	})
}

func (s *MetricTestSuite) verifyCount(counterVec *prometheus.CounterVec, expected int, labels ...string) {
	counter, err := counterVec.GetMetricWithLabelValues(labels...)
	require.NoError(s.T(), err)
	metric := &dto.Metric{}
	err = counter.Write(metric)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), expected, int(metric.Counter.GetValue()))
}

func (s *MetricTestSuite) TestMetricsEndpointExposesSpecificMetrics() {
	// given
	metric.RegisterMetrics()
	defer metric.UnregisterMetrics()
	metric.RecordUserDeactivationNotification(true)
	metric.RecordUserDeactivation(true)
	// when
	handler := promhttp.Handler()
	request := httptest.NewRequest("GET", "/metrics", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	// then
	body, err := ioutil.ReadAll(response.Body)
	require.NoError(s.T(), err)
	assert.Contains(s.T(), string(body), metric.UserDeactivationNotificationCounterName)
	assert.Contains(s.T(), string(body), metric.UserDeactivationCounterName)
}
