package metric

import (
	"github.com/fabric8-services/fabric8-common/log"
	metricsupport "github.com/fabric8-services/fabric8-common/metric"

	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	userDeactivationNotificationCounterName string = "user_deactivation_notification_total"
	userDeactivationCounterName             string = "user_deactivation_total"
)

var (
	userDeactivationNotificationCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: userDeactivationNotificationCounterName,
		Help: "Total number of the users notified for upcoming deactivation",
	}, []string{"successful", "failure"})
	userDeactivationCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: userDeactivationCounterName,
		Help: "Total number of the deactivated users",
	}, []string{"successful", "failure"})
)

// RegisterMetrics registers the service-specific metrics
func RegisterMetrics() {
	userDeactivationNotificationCounter = metricsupport.Register(*userDeactivationNotificationCounter, userDeactivationNotificationCounterName).(*prometheus.CounterVec)
	userDeactivationCounter = metricsupport.Register(*userDeactivationCounter, userDeactivationCounterName).(*prometheus.CounterVec)
	log.Info(nil, nil, "user deactivation/notification metrics registered successfully")
}

// RecordUserDeactivationNotification records a new user deactivation notification in the prometheus metric
func RecordUserDeactivationNotification(successful bool) {
	if counter, err := userDeactivationCounter.GetMetricWithLabelValues(strconv.FormatBool(successful)); err != nil {
		log.Error(nil, map[string]interface{}{
			"metric_name": userDeactivationNotificationCounterName,
			"successful":  successful,
			"err":         err,
		}, "Failed to get metric")
	} else {
		counter.Inc()
	}
}
// RecordUserDeactivation records a new user deactivation in the prometheus metric
func RecordUserDeactivation(successful bool) {
	if counter, err := userDeactivationCounter.GetMetricWithLabelValues(strconv.FormatBool(successful)); err != nil {
		log.Error(nil, map[string]interface{}{
			"metric_name": userDeactivationCounterName,
			"successful":  successful,
			"err":         err,
		}, "Failed to get metric")
	} else {
		counter.Inc()
	}
}

