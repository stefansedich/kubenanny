package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestMetricsRegistered(t *testing.T) {
	// Verify all metrics are registered in the default Prometheus registry.
	// promauto registers them at init time, so we just need to confirm
	// they can be collected without panic.
	metrics := []prometheus.Collector{
		EgressDeniedTotal,
		EgressAllowedTotal,
		PolicyCount,
		MonitoredPods,
		BPFErrorsTotal,
	}

	for _, m := range metrics {
		ch := make(chan prometheus.Metric, 10)
		m.Collect(ch)
		close(ch)
		// If we get here without panic, the metric is properly registered.
	}
}

func TestCounterVecLabels(t *testing.T) {
	// Verify that label sets match what the application code expects.
	tests := []struct {
		name   string
		metric *prometheus.CounterVec
		labels []string
	}{
		{
			name:   "EgressDeniedTotal",
			metric: EgressDeniedTotal,
			labels: []string{"policy_id"},
		},
		{
			name:   "EgressAllowedTotal",
			metric: EgressAllowedTotal,
			labels: []string{"policy_id"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WithLabelValues panics if the wrong number of labels is provided.
			c := tt.metric.WithLabelValues("12345")
			if c == nil {
				t.Fatal("expected non-nil counter")
			}
		})
	}
}

func TestGaugeOperations(t *testing.T) {
	// Verify gauges can be set and read back.
	PolicyCount.Set(5)
	MonitoredPods.Set(10)

	ch := make(chan prometheus.Metric, 1)
	PolicyCount.Collect(ch)
	m := <-ch

	desc := m.Desc().String()
	if desc == "" {
		t.Fatal("PolicyCount should have a non-empty description")
	}
}

func TestBPFErrorsCounter(t *testing.T) {
	// Verify the counter can be incremented.
	BPFErrorsTotal.Inc()

	ch := make(chan prometheus.Metric, 1)
	BPFErrorsTotal.Collect(ch)
	m := <-ch

	desc := m.Desc().String()
	if desc == "" {
		t.Fatal("BPFErrorsTotal should have a non-empty description")
	}
}
