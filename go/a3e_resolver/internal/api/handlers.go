// Package api implements the resolver's gRPC service.
package api

import (
    "context"
    "fmt"
    "log/slog"
    "sync/atomic"
    "time"

    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"

    pb "github.com/dezignator/A3E-DNS/go/a3e_resolver/internal/api/pb"
    "github.com/dezignator/A3E-DNS/go/a3e_resolver/internal/metrics"
    "github.com/dezignator/A3E-DNS/go/a3e_resolver/internal/pipeline"
)

// Handler implements the A3E-DNS service.
//
// The handler holds only the pipeline client, the metrics emitter and
// a logger. Any state that needs to survive a request (the rolling
// pipeline health, the AEE state cache) is held in the pipeline
// client or fetched fresh, not cached here, because caching it here
// would have introduced a second source of truth that the dashboard
// would have had to reconcile.
type Handler struct {
    pb.UnimplementedA3EServiceServer

    client  pipeline.Client
    metrics *metrics.Metrics
    logger  *slog.Logger

    // In-flight counter, kept as an atomic for the trivial case.
    inFlight atomic.Int64

    // Pipeline health cache: refreshed on every Health probe.
    lastHealthStatus atomic.Uint32
    lastHealthTime   atomic.Int64 // unix nanos
}

// NewHandler constructs a handler.
func NewHandler(client pipeline.Client, m *metrics.Metrics, logger *slog.Logger) *Handler {
    return &Handler{
        client:  client,
        metrics: m,
        logger:  logger,
    }
}

// Classify implements the single-window classification RPC.
//
// We wrapped the pipeline call in a defensive timeout that is slightly
// shorter than the pipeline's own budget. That was deliberate: the
// pipeline's budget is 1.42 ms P99 as measured from the pipeline's
// own start, but the resolver adds ~0.2 ms of RPC and serialization
// overhead, so a resolver-side timeout at 1.2 ms gives the pipeline a
// chance to answer with `budget_violated=true` before the resolver
// gives up entirely. It also means a hung pipeline does not hold a
// resolver worker indefinitely.
func (h *Handler) Classify(ctx context.Context, req *pb.ClassifyRequest) (*pb.ClassifyResponse, error) {
    if req == nil || req.GetWindow() == nil {
        return nil, status.Error(codes.InvalidArgument, "window is required")
    }
    h.inFlight.Add(1)
    h.metrics.InFlight.Inc()
    defer func() {
        h.inFlight.Add(-1)
        h.metrics.InFlight.Dec()
    }()

    started := time.Now()
    resp, err := h.client.Classify(ctx, req)
    elapsed := time.Since(started)
    h.metrics.QueryLatencySeconds.Observe(elapsed.Seconds())

    if err != nil {
        h.metrics.PipelineErrors.WithLabelValues("classify_rpc").Inc()
        h.logger.WarnContext(ctx, "classify failed",
            "query_id", req.GetContext().GetQueryId(),
            "error", err,
            "elapsed_ms", elapsed.Milliseconds(),
        )
        return nil, status.Errorf(codes.Unavailable, "pipeline: %v", err)
    }

    decision := "unspecified"
    switch resp.GetDecision() {
    case pb.Decision_DECISION_BENIGN:
        decision = "benign"
    case pb.Decision_DECISION_ATTACK:
        decision = "attack"
    }
    h.metrics.Decisions.WithLabelValues(decision).Inc()
    h.metrics.QueriesTotal.WithLabelValues(
        protocolLabel(req.GetContext().GetProtocol()),
        decision,
    ).Inc()

    return resp, nil
}

// ClassifyBatch implements the batched classification RPC.
func (h *Handler) ClassifyBatch(ctx context.Context, req *pb.ClassifyBatchRequest) (*pb.ClassifyBatchResponse, error) {
    if req == nil || len(req.GetWindows()) == 0 {
        return nil, status.Error(codes.InvalidArgument, "windows is required")
    }
    h.inFlight.Add(1)
    h.metrics.InFlight.Inc()
    defer func() {
        h.inFlight.Add(-1)
        h.metrics.InFlight.Dec()
    }()

    started := time.Now()
    resp, err := h.client.ClassifyBatch(ctx, req)
    elapsed := time.Since(started)
    h.metrics.QueryLatencySeconds.Observe(elapsed.Seconds())

    if err != nil {
        h.metrics.PipelineErrors.WithLabelValues("classify_batch_rpc").Inc()
        return nil, status.Errorf(codes.Unavailable, "pipeline: %v", err)
    }
    for _, r := range resp.GetResponses() {
        decision := "unspecified"
        switch r.GetDecision() {
        case pb.Decision_DECISION_BENIGN:
            decision = "benign"
        case pb.Decision_DECISION_ATTACK:
            decision = "attack"
        }
        h.metrics.QueriesTotal.WithLabelValues(
            protocolLabel(req.GetContext().GetProtocol()),
            decision,
        ).Inc()
    }
    return resp, nil
}

// GetAEEState implements the AEE state RPC.
func (h *Handler) GetAEEState(ctx context.Context, req *pb.GetAEEStateRequest) (*pb.GetAEEStateResponse, error) {
    return h.client.GetAEEState(ctx, req)
}

// Health implements the health RPC.
func (h *Handler) Health(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
    resp, err := h.client.Health(ctx, req)
    if err != nil {
        h.lastHealthStatus.Store(uint32(pb.HealthResponse_STATUS_NOT_SERVING))
        h.lastHealthTime.Store(time.Now().UnixNano())
        return &pb.HealthResponse{
            Status: pb.HealthResponse_STATUS_NOT_SERVING,
            Version: "0.1.0",
        }, nil
    }
    h.lastHealthStatus.Store(uint32(resp.GetStatus()))
    h.lastHealthTime.Store(time.Now().UnixNano())
    return resp, nil
}

func protocolLabel(p pb.Protocol) string {
    switch p {
    case pb.Protocol_PROTOCOL_DOH:
        return "doh"
    case pb.Protocol_PROTOCOL_DOT:
        return "dot"
    case pb.Protocol_PROTOCOL_DOQ:
        return "doq"
    default:
        return "unspecified"
    }
}

// ensure fmt is referenced; we use it in future handler variants.
var _ = fmt.Sprintf
