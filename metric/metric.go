package metric

import (
	"github.com/fabric8-services/fabric8-auth/log"
	metricsupport "github.com/fabric8-services/fabric8-common/metric"

	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	// UserDeactivationNotificationCounterName the name of the user deactivation notification counter
	UserDeactivationNotificationCounterName string = "user_deactivation_notification_total" // PCP automatically rate-converts *_total counters to Hz. So, we don't use _total in the name to avoid that conversion
	// UserDeactivationTriggerCounterName the name of the user deactivation trigger counter
	UserDeactivationTriggerCounterName string = "user_deactivation_trigger_total"
	// UserDeactivationCounterName the name of the user deactivation counter
	UserDeactivationCounterName string = "user_deactivation_total"
)

var (
	// UserDeactivationNotificationCounter counts the number of notifications sent to users
	UserDeactivationNotificationCounter *prometheus.CounterVec
	// UserDeactivationTriggerCounter counts the user deactivation triggers
	UserDeactivationTriggerCounter *prometheus.CounterVec
	// UserDeactivationCounter counts the user deactivations
	UserDeactivationCounter *prometheus.CounterVec
)

// RegisterMetrics registers the service-specific metrics
func RegisterMetrics() {
	UserDeactivationNotificationCounter = metricsupport.Register(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: UserDeactivationNotificationCounterName,
		Help: "Total number of users notified for deactivation",
	}, []string{"successful"}), UserDeactivationNotificationCounterName).(*prometheus.CounterVec)
	UserDeactivationTriggerCounter = metricsupport.Register(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: UserDeactivationTriggerCounterName,
		Help: "Total number of user deactivatation triggers",
	}, []string{"successful"}), UserDeactivationTriggerCounterName).(*prometheus.CounterVec)
	UserDeactivationCounter = metricsupport.Register(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: UserDeactivationCounterName,
		Help: "Total number of deactivated users",
	}, []string{"successful"}), UserDeactivationCounterName).(*prometheus.CounterVec)
	log.Info(nil, nil, "user deactivation/notification metrics registered successfully")
}

// UnregisterMetrics un-registers the service-specific metrics
func UnregisterMetrics() {
	prometheus.Unregister(*UserDeactivationNotificationCounter)
	prometheus.Unregister(*UserDeactivationCounter)
	log.Info(nil, nil, "user deactivation/notification metrics unregistered successfully")
}

// RecordUserDeactivationNotification records a new user deactivation notification in the prometheus metric
func RecordUserDeactivationNotification(successful bool) {
	if UserDeactivationNotificationCounter == nil {
		log.Warn(nil, map[string]interface{}{
			"metric_name": UserDeactivationNotificationCounterName,
		}, "metric not initialized")
		return
	}
	if counter, err := UserDeactivationNotificationCounter.GetMetricWithLabelValues(strconv.FormatBool(successful)); err != nil {
		log.Error(nil, map[string]interface{}{
			"metric_name": UserDeactivationNotificationCounterName,
			"successful":  successful,
			"err":         err,
		}, "Failed to increment metric")
	} else {
		log.Info(nil, map[string]interface{}{
			"metric_name": UserDeactivationNotificationCounterName,
			"successful":  successful,
		}, "incremented metric")
		counter.Inc()
	}
}

// RecordUserDeactivationTrigger records a new user deactivation trigger in the prometheus metric
func RecordUserDeactivationTrigger(successful bool) {
	if UserDeactivationTriggerCounter == nil {
		log.Warn(nil, map[string]interface{}{
			"metric_name": UserDeactivationTriggerCounterName,
		}, "metric not initialized")
		return
	}
	if counter, err := UserDeactivationTriggerCounter.GetMetricWithLabelValues(strconv.FormatBool(successful)); err != nil {
		log.Error(nil, map[string]interface{}{
			"metric_name": UserDeactivationTriggerCounterName,
			"successful":  successful,
			"err":         err,
		}, "Failed to get metric")
	} else {
		log.Info(nil, map[string]interface{}{
			"metric_name": UserDeactivationTriggerCounterName,
			"successful":  successful,
		}, "incremented metric")
		counter.Inc()
	}
}

// RecordUserDeactivation records a new user deactivation in the prometheus metric
func RecordUserDeactivation(successful bool) {
	if UserDeactivationCounter == nil {
		log.Warn(nil, map[string]interface{}{
			"metric_name": UserDeactivationCounterName,
		}, "metric not initialized")
		return
	}
	if counter, err := UserDeactivationCounter.GetMetricWithLabelValues(strconv.FormatBool(successful)); err != nil {
		log.Error(nil, map[string]interface{}{
			"metric_name": UserDeactivationCounterName,
			"successful":  successful,
			"err":         err,
		}, "Failed to get metric")
	} else {
		log.Info(nil, map[string]interface{}{
			"metric_name": UserDeactivationCounterName,
			"successful":  successful,
		}, "incremented metric")
		counter.Inc()
	}
}
