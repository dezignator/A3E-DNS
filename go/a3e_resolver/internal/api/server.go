// Package api: the gRPC server lifecycle.
package api

import (
    "context"
    "crypto/tls"
    "errors"
    "fmt"
    "log/slog"
    "net"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/prometheus/client_golang/prometheus/promhttp"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    "google.golang.org/grpc/health"
    "google.golang.org/grpc/health/grpc_health_v1"
    "google.golang.org/grpc/keepalive"
    "google.golang.org/grpc/reflection"

    pb "github.com/dezignator/A3E-DNS/go/a3e_resolver/internal/api/pb"
    "github.com/dezignator/A3E-DNS/go/a3e_resolver/internal/config"
    "github.com/dezignator/A3E-DNS/go/a3e_resolver/internal/metrics"
    "github.com/dezignator/A3E-DNS/go/a3e_resolver/internal/pipeline"
)

// Server holds the resolver's listener, gRPC server, Prometheus
// exporter and the signal-driven shutdown handler.
type Server struct {
    cfg     *config.Config
    metrics *metrics.Metrics
    logger  *slog.Logger
    client  pipeline.Client

    grpcServer  *grpc.Server
    healthServer *health.Server
    httpServer  *http.Server

    shutdownFns []func(context.Context) error
}

// New builds a Server. The caller invokes Run to start it.
func New(cfg *config.Config, logger *slog.Logger) (*Server, error) {
    m := metrics.New(cfg.Metrics.Namespace, cfg.Metrics.Subsystem)

    client, err := pipeline.New(&cfg.Pipeline, m)
    if err != nil {
        return nil, fmt.Errorf("pipeline client: %w", err)
    }

    s := &Server{
        cfg:     cfg,
        metrics: m,
        logger:  logger,
        client:  client,
    }
    s.shutdownFns = append(s.shutdownFns, client.Close)

    if err := s.buildGRPCServer(); err != nil {
        return nil, err
    }
    if err := s.buildHTTPServer(); err != nil {
        return nil, err
    }
    return s, nil
}

// buildGRPCServer constructs the gRPC server and registers services.
func (s *Server) buildGRPCServer() error {
    var opts []grpc.ServerOption
    opts = append(opts, grpc.MaxConcurrentStreams(uint32(s.cfg.Server.MaxConcurrent)))
    opts = append(opts, grpc.KeepaliveParams(keepalive.ServerParameters{
        MaxConnectionIdle: 30 * time.Minute,
        Time:              30 * time.Second,
        Timeout:           10 * time.Second,
    }))
    opts = append(opts, grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
        MinTime:             10 * time.Second,
        PermitWithoutStream: true,
    }))

    // The resolver's own gRPC server does not require mTLS because it
    // is intended to sit behind the resolver's own ingress, which
    // handles external authentication. If the deployment topology
    // changes to expose the resolver gRPC endpoint directly, the
    // operator should add the credentials here from the same TLS
    // configuration the pipeline uses.
    if s.cfg.Pipeline.TLSCertPath != "" && s.cfg.Pipeline.TLSKeyPath != "" {
        cert, err := tls.LoadX509KeyPair(
            s.cfg.Pipeline.TLSCertPath,
            s.cfg.Pipeline.TLSKeyPath,
        )
        if err != nil {
            return fmt.Errorf("load server TLS key pair: %w", err)
        }
        opts = append(opts, grpc.Creds(credentials.NewTLS(&tls.Config{
            Certificates: []tls.Certificate{cert},
            MinVersion:   tls.VersionTLS13,
        })))
    }

    s.grpcServer = grpc.NewServer(opts...)

    handler := NewHandler(s.client, s.metrics, s.logger)
    pb.RegisterA3EServiceServer(s.grpcServer, handler)

    s.healthServer = health.NewServer()
    s.healthServer.SetServingStatus("a3e.v1.A3EService", grpc_health_v1.HealthCheckResponse_SERVING)
    grpc_health_v1.RegisterHealthServer(s.grpcServer, s.healthServer)

    // We enabled reflection so that an operator can inspect the
    // service with grpcurl during a live deployment. The reflection
    // API exposes only the public schema; the internal package
    // (a3e.v1.internal) is not registered with the resolver's
    // reflection service.
    reflection.Register(s.grpcServer)

    return nil
}

// buildHTTPServer constructs the Prometheus exporter.
func (s *Server) buildHTTPServer() error {
    mux := http.NewServeMux()
    mux.Handle(s.cfg.Metrics.Path, promhttp.HandlerFor(
        s.metrics.Registry(),
        promhttp.HandlerOpts{
            ErrorHandling: promhttp.ContinueOnError,
        },
    ))
    mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        _, _ = w.Write([]byte("ok"))
    })

    s.httpServer = &http.Server{
        Addr:         s.cfg.Metrics.ListenAddress,
        Handler:      mux,
        ReadTimeout:  5 * time.Second,
        WriteTimeout: 10 * time.Second,
        IdleTimeout:  60 * time.Second,
    }
    return nil
}

// Run starts the servers and blocks until a shutdown signal or a
// fatal error.
func (s *Server) Run(ctx context.Context) error {
    grpcListener, err := net.Listen("tcp", s.cfg.Server.ListenAddress)
    if err != nil {
        return fmt.Errorf("listen gRPC %q: %w", s.cfg.Server.ListenAddress, err)
    }

    httpListener, err := net.Listen("tcp", s.cfg.Metrics.ListenAddress)
    if err != nil {
        _ = grpcListener.Close()
        return fmt.Errorf("listen metrics %q: %w", s.cfg.Metrics.ListenAddress, err)
    }

    errCh := make(chan error, 2)
    go func() {
        s.logger.Info("gRPC server listening", "address", s.cfg.Server.ListenAddress)
        if err := s.grpcServer.Serve(grpcListener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
            errCh <- fmt.Errorf("gRPC server: %w", err)
        }
    }()
    go func() {
        s.logger.Info("metrics server listening", "address", s.cfg.Metrics.ListenAddress)
        if err := s.httpServer.Serve(httpListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
            errCh <- fmt.Errorf("metrics server: %w", err)
        }
    }()

    // Signal handler.
    sigCh := make(chan os.Signal, 2)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
    select {
    case <-ctx.Done():
        s.logger.Info("context canceled, initiating shutdown")
    case sig := <-sigCh:
        s.logger.Info("signal received, initiating shutdown", "signal", sig.String())
    case err := <-errCh:
        s.logger.Error("server error", "error", err)
        return err
    }

    shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.Server.ShutdownTimeout)
    defer cancel()

    s.healthServer.Shutdown()
    s.grpcServer.GracefulStop()
    if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
        s.logger.Error("http shutdown error", "error", err)
    }
    for _, fn := range s.shutdownFns {
        if err := fn(shutdownCtx); err != nil {
            s.logger.Warn("shutdown function error", "error", err)
        }
    }
    s.logger.Info("shutdown complete")
    return nil
}
