// Package pipeline is the resolver's client for the A3E-DNS Python
// pipeline.
//
// We wrapped the gRPC client in this package rather than calling gRPC
// directly from the handlers because the retry policy, the timeout
// propagation, the batch aggregation and the metrics emission are all
// cross-cutting concerns that would otherwise have been duplicated in
// every handler. The wrapper exposes a small interface so that the
// handlers can be tested against a mock without a running pipeline.
package pipeline

import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "errors"
    "fmt"
    "io"
    "os"
    "sync"
    "time"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    "google.golang.org/grpc/credentials/insecure"
    "google.golang.org/grpc/status"

    pb "github.com/dezignator/A3E-DNS/go/a3e_resolver/internal/api/pb"
    "github.com/dezignator/A3E-DNS/go/a3e_resolver/internal/config"
    "github.com/dezignator/A3E-DNS/go/a3e_resolver/internal/metrics"
)

// Client is the resolver's interface to the Python pipeline.
type Client interface {
    Classify(ctx context.Context, req *pb.ClassifyRequest) (*pb.ClassifyResponse, error)
    ClassifyBatch(ctx context.Context, req *pb.ClassifyBatchRequest) (*pb.ClassifyBatchResponse, error)
    GetAEEState(ctx context.Context, req *pb.GetAEEStateRequest) (*pb.GetAEEStateResponse, error)
    Health(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error)
    Close() error
}

// GRPCClient is the production client.
//
// The client holds a single gRPC connection and reuses it for all
// requests. gRPC's own connection pooling already handles multiplexing
// over one HTTP/2 connection, so reusing the connection is both
// cheaper and lower-latency than reconnecting per request.
type GRPCClient struct {
    cfg     *config.PipelineConfig
    metrics *metrics.Metrics

    conn   *grpc.ClientConn
    client pb.A3EServiceClient

    mu              sync.Mutex
    lastHealthOK    time.Time
    lastHealthCount uint64
}

// New creates a GRPCClient.
func New(cfg *config.PipelineConfig, m *metrics.Metrics) (*GRPCClient, error) {
    if cfg == nil {
        return nil, errors.New("config is nil")
    }

    opts := []grpc.DialOption{
        grpc.WithBlock(),
    }
    if cfg.InsecureSkipVerify {
        opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
    } else {
        creds, err := loadCredentials(cfg)
        if err != nil {
            return nil, fmt.Errorf("load TLS credentials: %w", err)
        }
        opts = append(opts, grpc.WithTransportCredentials(creds))
    }

    ctx, cancel := context.WithTimeout(context.Background(), cfg.DialTimeout)
    defer cancel()

    conn, err := grpc.DialContext(ctx, cfg.Endpoint, opts...)
    if err != nil {
        return nil, fmt.Errorf("dial %q: %w", cfg.Endpoint, err)
    }

    return &GRPCClient{
        cfg:     cfg,
        metrics: m,
        conn:    conn,
        client:  pb.NewA3EServiceClient(conn),
    }, nil
}

// loadCredentials builds a TLS client config from the paths in cfg.
func loadCredentials(cfg *config.PipelineConfig) (credentials.TransportCredentials, error) {
    cert, err := tls.LoadX509KeyPair(cfg.TLSCertPath, cfg.TLSKeyPath)
    if err != nil {
        return nil, fmt.Errorf("load client key pair: %w", err)
    }
    pool := x509.NewCertPool()
    ca, err := os.ReadFile(cfg.TLSCAPath)
    if err != nil {
        return nil, fmt.Errorf("read CA %q: %w", cfg.TLSCAPath, err)
    }
    if !pool.AppendCertsFromPEM(ca) {
        return nil, errors.New("failed to append CA certificates")
    }
    return credentials.NewTLS(&tls.Config{
        Certificates: []tls.Certificate{cert},
        RootCAs:      pool,
        ServerName:   hostname(cfg.Endpoint),
        MinVersion:   tls.VersionTLS13,
    }), nil
}

func hostname(endpoint string) string {
    // We stripped the port; the TLS verification needs only the host.
    for i := len(endpoint) - 1; i >= 0; i-- {
        if endpoint[i] == ':' {
            return endpoint[:i]
        }
    }
    return endpoint
}

// Classify issues a single classification request with retry.
func (c *GRPCClient) Classify(ctx context.Context, req *pb.ClassifyRequest) (*pb.ClassifyResponse, error) {
    ctx, cancel := context.WithTimeout(ctx, c.cfg.RequestTimeout)
    defer cancel()

    var lastErr error
    backoff := c.cfg.RetryBackoffBase
    for attempt := 0; attempt <= c.cfg.MaxRetries; attempt++ {
        started := time.Now()
        resp, err := c.client.Classify(ctx, req)
        c.metrics.PipelineLatencySeconds.Observe(time.Since(started).Seconds())
        if err == nil {
            if resp.GetBudgetViolated() {
                c.metrics.BudgetViolations.Inc()
            }
            if resp.GetAttestation() != nil {
                c.metrics.AttestationOutcomes.WithLabelValues(
                    attestationLabel(resp.GetAttestation().GetOutcome()),
                ).Inc()
            }
            c.metrics.MorphOutcomes.WithLabelValues(
                morphLabel(resp.GetMorph()),
            ).Inc()
            c.metrics.IncQueriesServed()
            return resp, nil
        }
        lastErr = err
        if !retryable(err) {
            c.metrics.PipelineErrors.WithLabelValues("non_retryable").Inc()
            return nil, err
        }
        c.metrics.PipelineErrors.WithLabelValues("retryable").Inc()
        if attempt == c.cfg.MaxRetries {
            break
        }
        select {
        case <-ctx.Done():
            return nil, ctx.Err()
        case <-time.After(backoff):
        }
        backoff *= 2
        if backoff > c.cfg.RetryBackoffMax {
            backoff = c.cfg.RetryBackoffMax
        }
    }
    return nil, lastErr
}

// ClassifyBatch issues a batched classification request.
//
// Unlike Classify, the batched path does not retry. Batches are
// large enough that a retry after a partial failure would re-run
// inference on the whole batch and lose any latency budget the
// caller had; the resolver's transport worker handles batch retries
// at a higher level.
func (c *GRPCClient) ClassifyBatch(ctx context.Context, req *pb.ClassifyBatchRequest) (*pb.ClassifyBatchResponse, error) {
    ctx, cancel := context.WithTimeout(ctx, c.cfg.RequestTimeout)
    defer cancel()

    c.metrics.BatchSizeHistogram.Observe(float64(len(req.GetWindows())))
    started := time.Now()
    resp, err := c.client.ClassifyBatch(ctx, req)
    c.metrics.PipelineLatencySeconds.Observe(time.Since(started).Seconds())
    if err != nil {
        c.metrics.PipelineErrors.WithLabelValues("batch").Inc()
        return nil, err
    }
    for _, r := range resp.GetResponses() {
        if r.GetBudgetViolated() {
            c.metrics.BudgetViolations.Inc()
        }
        c.metrics.IncQueriesServed()
    }
    return resp, nil
}

// GetAEEState fetches the current AEE state.
func (c *GRPCClient) GetAEEState(ctx context.Context, req *pb.GetAEEStateRequest) (*pb.GetAEEStateResponse, error) {
    ctx, cancel := context.WithTimeout(ctx, c.cfg.RequestTimeout)
    defer cancel()
    return c.client.GetAEEState(ctx, req)
}

// Health probes the pipeline.
func (c *GRPCClient) Health(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
    ctx, cancel := context.WithTimeout(ctx, c.cfg.RequestTimeout)
    defer cancel()

    resp, err := c.client.Health(ctx, req)
    c.mu.Lock()
    defer c.mu.Unlock()
    if err == nil {
        if c.lastHealthOK.IsZero() {
            // First successful health check; record the baseline.
            c.lastHealthCount = resp.GetQueriesServed()
        } else if resp.GetQueriesServed() < c.lastHealthCount {
            // Counter went backwards, which means the pipeline restarted.
            c.metrics.IncPipelineRestarts()
        }
        c.lastHealthCount = resp.GetQueriesServed()
        c.lastHealthOK = time.Now()
    }
    return resp, err
}

// Close terminates the gRPC connection.
func (c *GRPCClient) Close() error {
    if c.conn != nil {
        return c.conn.Close()
    }
    return nil
}

// retryable reports whether an error is worth retrying.
func retryable(err error) bool {
    if err == nil {
        return false
    }
    if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
        // Deadline exceeded is not retryable because the caller has
        // already lost the budget; context canceled is not retryable
        // because the caller explicitly canceled.
        return false
    }
    if errors.Is(err, io.EOF) {
        return true
    }
    st, ok := status.FromError(err)
    if !ok {
        return true
    }
    switch st.Code() {
    case 1, 2, 4, 8, 10, 13, 14:
        // CANCELLED, UNKNOWN, DEADLINE_EXCEEDED, RESOURCE_EXHAUSTED,
        // ABORTED, INTERNAL, UNAVAILABLE.
        return st.Code() != 1 && st.Code() != 4
    default:
        return false
    }
}

func attestationLabel(o pb.AttestationHandle_Outcome) string {
    switch o {
    case pb.AttestationHandle_OUTCOME_VERIFIED:
        return "verified"
    case pb.AttestationHandle_OUTCOME_FAILED:
        return "failed"
    case pb.AttestationHandle_OUTCOME_SKIPPED:
        return "skipped"
    default:
        return "unspecified"
    }
}

func morphLabel(o pb.MorphOutcome) string {
    switch o {
    case pb.MorphOutcome_MORPH_OUTCOME_NO_CHANGE:
        return "no_change"
    case pb.MorphOutcome_MORPH_OUTCOME_MORPHED:
        return "morphed"
    case pb.MorphOutcome_MORPH_OUTCOME_SUPPRESSED:
        return "suppressed"
    case pb.MorphOutcome_MORPH_OUTCOME_DISABLED:
        return "disabled"
    default:
        return "unspecified"
    }
}
