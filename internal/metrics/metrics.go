// Package metrics exposes Prometheus metrics for kubenanny.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// EgressDeniedTotal counts denied egress connections.
	EgressDeniedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kubenanny_egress_denied_total",
		Help: "Total number of denied egress connections.",
	}, []string{"policy_id"})

	// EgressAllowedTotal counts allowed egress connections.
	EgressAllowedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kubenanny_egress_allowed_total",
		Help: "Total number of allowed egress connections.",
	}, []string{"policy_id"})

	// PolicyCount tracks the number of active EgressPolicy resources.
	PolicyCount = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "kubenanny_policy_count",
		Help: "Number of active EgressPolicy resources.",
	})

	// MonitoredPods tracks the number of pods with active egress policies.
	MonitoredPods = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "kubenanny_monitored_pods",
		Help: "Number of pods with active egress filtering.",
	})

	// BPFErrorsTotal counts BPF-related errors.
	BPFErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kubenanny_bpf_errors_total",
		Help: "Total number of BPF-related errors.",
	})
)
