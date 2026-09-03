// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2024 Canonical Ltd.

/*
 *  Metrics package is used to expose the metrics of the PCF service.
 */

package metrics

import (
	"net/http"

	"github.com/omec-project/pcf/logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// labelResult is the outcome label shared by every counter here.
const labelResult = "result"

// PcfStats captures PCF stats
type PcfStats struct {
	pcfSmPolicy            *prometheus.CounterVec
	pcfPolicyAuthorization *prometheus.CounterVec
	pcfPolicyNotify        *prometheus.CounterVec
}

var pcfStats *PcfStats

func initPcfStats() *PcfStats {
	return &PcfStats{
		pcfSmPolicy: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pcf_smpolicy",
			Help: "Counter of total Session Management policy queries",
		}, []string{"query_type", "dnn", labelResult}),
		pcfPolicyAuthorization: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pcf_policy_authorization",
			Help: "Counter of total policy authorization queries",
		}, []string{"query_type", "resource_type", labelResult}),
		pcfPolicyNotify: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pcf_policy_notify",
			Help: "Counter of established-session policy change notifications by outcome",
		}, []string{labelResult}),
	}
}

func (ps *PcfStats) register() error {
	if err := prometheus.Register(ps.pcfSmPolicy); err != nil {
		return err
	}
	if err := prometheus.Register(ps.pcfPolicyAuthorization); err != nil {
		return err
	}
	if err := prometheus.Register(ps.pcfPolicyNotify); err != nil {
		return err
	}
	return nil
}

func init() {
	pcfStats = initPcfStats()

	if err := pcfStats.register(); err != nil {
		logger.InitLog.Errorln("PCF Stats register failed")
	}
}

// InitMetrics initializes PCF metrics
func InitMetrics() {
	http.Handle("/metrics", promhttp.Handler())
	if err := http.ListenAndServe(":8080", nil); err != nil {
		logger.InitLog.Errorf("Could not open metrics port: %v", err)
	}
}

// IncrementPcfSmPolicyStats increments number of total Session Management policy queries
func IncrementPcfSmPolicyStats(queryType, dnn, result string) {
	pcfStats.pcfSmPolicy.WithLabelValues(queryType, dnn, result).Inc()
}

// IncrementPcfPolicyAuthorizationStats increments number of total policy authorization queries
func IncrementPcfPolicyAuthorizationStats(queryType, resourceType, result string) {
	pcfStats.pcfPolicyAuthorization.WithLabelValues(queryType, resourceType, result).Inc()
}

// AddPcfPolicyNotifyStats records the outcome of established-session policy change notifications.
//
// A session counted as anything other than "delivered" is still on its previous policy while the
// PCF's configuration says otherwise, and nothing re-drives it until the policy changes again.
// That divergence is invisible in logs alone, which is why it is counted.
func AddPcfPolicyNotifyStats(result string, count int) {
	if count <= 0 {
		return
	}
	pcfStats.pcfPolicyNotify.WithLabelValues(result).Add(float64(count))
}
