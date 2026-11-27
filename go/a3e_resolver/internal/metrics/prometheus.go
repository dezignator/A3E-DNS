// Package metrics wires up the Prometheus exporters the resolver
// exposes. We chose Prometheus over OpenTelemetry for the resolver
// because the reference deployment already ran Prometheus for the host
// metrics, and adding a second telemetry system would have doubled the
// operational burden for a benefit the thesis does not discuss.
package metrics

import (
    "fmt"
    "sync/atomic"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds the resolver's Prometheus collectors.
//
// We kept the collectors as fields rather than globals so that tests
// can create an isolated registry per test case. A global registry
// would have leaked state between tests and made flaky tests hard to
// diagnose.
type Metrics struct {
    registry *prometheus.Registry

    QueriesTotal          *prometheus.CounterVec
    QueryLatencySeconds   prometheus.Histogram
    PipelineLatencySeconds prometheus.Histogram
    PipelineErrors        *prometheus.CounterVec
    BudgetViolations      prometheus.Counter
    Decisions             *prometheus.CounterVec
    BatchSizeHistogram    prometheus.Histogram
    InFlight              prometheus.Gauge
    AttestationOutcomes   *prometheus.CounterVec
    MorphOutcomes         *prometheus.CounterVec

    // Counters we maintain internally and expose on demand.
    queriesServed atomic.Uint64
    pipelineRestarts atomic.Uint64
}

// New creates and registers a fresh set of collectors.
func New(namespace, subsystem string) *Metrics {
    reg := prometheus.NewRegistry()
    factory := promauto.With(reg)

    m := &Metrics{registry: reg}
    m.QueriesTotal = factory.NewCounterVec(
        prometheus.CounterOpts{
            Namespace: namespace,
            Subsystem: subsystem,
            Name:      "queries_total",
            Help:      "Total number of DNS queries classified by the resolver.",
        },
        []string{"protocol", "decision"},
    )
    m.QueryLatencySeconds = factory.NewHistogram(
        prometheus.HistogramOpts{
            Namespace: namespace,
            Subsystem: subsystem,
            Name:      "query_latency_seconds",
            Help:      "Total resolver-side latency per query.",
            Buckets:   prometheus.ExponentialBuckets(0.00005, 2.0, 16),
        },
    )
    m.PipelineLatencySeconds = factory.NewHistogram(
        prometheus.HistogramOpts{
            Namespace: namespace,
            Subsystem: subsystem,
            Name:      "pipeline_latency_seconds",
            Help:      "Latency of the RPC to the Python pipeline.",
            Buckets:   prometheus.ExponentialBuckets(0.00005, 2.0, 16),
        },
    )
    m.PipelineErrors = factory.NewCounterVec(
        prometheus.CounterOpts{
            Namespace: namespace,
            Subsystem: subsystem,
            Name:      "pipeline_errors_total",
            Help:      "Total pipeline RPC errors by category.",
        },
        []string{"category"},
    )
    m.BudgetViolations = factory.NewCounter(
        prometheus.CounterOpts{
            Namespace: namespace,
            Subsystem: subsystem,
            Name:      "budget_violations_total",
            Help:      "Total queries where the pipeline reported a latency budget violation.",
        },
    )
    m.Decisions = factory.NewCounterVec(
        prometheus.CounterOpts{
            Namespace: namespace,
            Subsystem: subsystem,
            Name:      "decisions_total",
            Help:      "Classification decisions by value.",
        },
        []string{"decision"},
    )
    m.BatchSizeHistogram = factory.NewHistogram(
        prometheus.HistogramOpts{
            Namespace: namespace,
            Subsystem: subsystem,
            Name:      "batch_size",
            Help:      "Distribution of batch sizes submitted to the pipeline.",
            Buckets:   prometheus.LinearBuckets(1, 8, 16),
        },
    )
    m.InFlight = factory.NewGauge(
        prometheus.GaugeOpts{
            Namespace: namespace,
            Subsystem: subsystem,
            Name:      "in_flight",
            Help:      "Number of queries currently being classified.",
        },
    )
    m.AttestationOutcomes = factory.NewCounterVec(
        prometheus.CounterOpts{
            Namespace: namespace,
            Subsystem: subsystem,
            Name:      "attestation_outcomes_total",
            Help:      "QHE attestation outcomes by value.",
        },
        []string{"outcome"},
    )
    m.MorphOutcomes = factory.NewCounterVec(
        prometheus.CounterOpts{
            Namespace: namespace,
            Subsystem: subsystem,
            Name:      "morph_outcomes_total",
            Help:      "AEE morph outcomes by value.",
        },
        []string{"outcome"},
    )
    return m
}

// Registry returns the underlying Prometheus registry, suitable for
// handing to promhttp.HandlerFor.
func (m *Metrics) Registry() *prometheus.Registry {
    return m.registry
}

// IncQueriesServed increments the monotonic served counter.
//
// That counter is exposed via the gRPC Health method so the resolver
// can detect a pipeline restart between two probes.
func (m *Metrics) IncQueriesServed() {
    m.queriesServed.Add(1)
}

// QueriesServed returns the current served count.
func (m *Metrics) QueriesServed() uint64 {
    return m.queriesServed.Load()
}

// IncPipelineRestarts increments the restart counter.
func (m *Metrics) IncPipelineRestarts() {
    m.pipelineRestarts.Add(1)
}

// PipelineRestarts returns the current restart count.
func (m *Metrics) PipelineRestarts() uint64 {
    return m.pipelineRestarts.Load()
}

// Describe implements prometheus.Collector for the Metrics type,
// exposing the internally tracked counters alongside the registered
// ones. The description is fixed (no labels), which was deliberate:
// the resolver only ever runs one instance per process, so labels
// would have added cardinality without information.
func (m *Metrics) Describe(ch chan<- *prometheus.Desc) {
    // The registered collectors describe themselves; we only need to
    // describe the two counters we maintain manually.
    served := prometheus.NewDesc(
        fmt.Sprintf("a3e_resolver_queries_served_total"),
        "Total queries served since process start.",
        nil, nil,
    )
    restarts := prometheus.NewDesc(
        fmt.Sprintf("a3e_resolver_pipeline_restarts_total"),
        "Number of pipeline restarts detected via the health method.",
        nil, nil,
    )
    ch <- served
    ch <- restarts
}

// Collect implements prometheus.Collector.
func (m *Metrics) Collect(ch chan<- prometheus.Metric) {
    served := prometheus.MustNewConstMetric(
        prometheus.NewDesc(
            "a3e_resolver_queries_served_total",
            "Total queries served since process start.",
            nil, nil,
        ),
        prometheus.CounterValue,
        float64(m.queriesServed.Load()),
    )
    restarts := prometheus.MustNewConstMetric(
        prometheus.NewDesc(
            "a3e_resolver_pipeline_restarts_total",
            "Number of pipeline restarts detected via the health method.",
            nil, nil,
        ),
        prometheus.CounterValue,
        float64(m.pipelineRestarts.Load()),
    )
    ch <- served
    ch <- restarts
}
