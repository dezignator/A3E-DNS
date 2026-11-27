package api

import (
    "context"
    "errors"
    "testing"

    "github.com/dezignator/A3E-DNS/go/a3e_resolver/internal/metrics"
    pb "github.com/dezignator/A3E-DNS/go/a3e_resolver/internal/api/pb"
)

// fakePipeline is a minimal pipeline.Client implementation for tests.
type fakePipeline struct {
    classifyResp *pb.ClassifyResponse
    classifyErr  error
    healthResp   *pb.HealthResponse
    healthErr    error
}

func (f *fakePipeline) Classify(ctx context.Context, req *pb.ClassifyRequest) (*pb.ClassifyResponse, error) {
    return f.classifyResp, f.classifyErr
}
func (f *fakePipeline) ClassifyBatch(ctx context.Context, req *pb.ClassifyBatchRequest) (*pb.ClassifyBatchResponse, error) {
    return nil, nil
}
func (f *fakePipeline) GetAEEState(ctx context.Context, req *pb.GetAEEStateRequest) (*pb.GetAEEStateResponse, error) {
    return nil, nil
}
func (f *fakePipeline) Health(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
    return f.healthResp, f.healthErr
}
func (f *fakePipeline) Close() error { return nil }

func newTestHandler(p *fakePipeline) *Handler {
    m := metrics.New("test", "resolver")
    return NewHandler(p, m, nil)
}

func TestClassifyRejectsNilWindow(t *testing.T) {
    h := newTestHandler(&fakePipeline{})
    _, err := h.Classify(context.Background(), &pb.ClassifyRequest{})
    if err == nil {
        t.Fatal("expected error for nil window")
    }
}

func TestClassifyPropagatesDecision(t *testing.T) {
    h := newTestHandler(&fakePipeline{
        classifyResp: &pb.ClassifyResponse{
            Decision:   pb.Decision_DECISION_ATTACK,
            Confidence: 0.97,
        },
    })
    resp, err := h.Classify(context.Background(), &pb.ClassifyRequest{
        Window: &pb.FeatureWindow{},
    })
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if resp.GetDecision() != pb.Decision_DECISION_ATTACK {
        t.Fatalf("expected ATTACK, got %v", resp.GetDecision())
    }
}

func TestClassifyMapsPipelineErrorToUnavailable(t *testing.T) {
    h := newTestHandler(&fakePipeline{
        classifyErr: errors.New("boom"),
    })
    _, err := h.Classify(context.Background(), &pb.ClassifyRequest{
        Window: &pb.FeatureWindow{},
    })
    if err == nil {
        t.Fatal("expected error")
    }
}

func TestHealthReportsNotServingOnError(t *testing.T) {
    h := newTestHandler(&fakePipeline{
        healthErr: errors.New("down"),
    })
    resp, err := h.Health(context.Background(), &pb.HealthRequest{})
    if err != nil {
        t.Fatalf("health should not propagate the error: %v", err)
    }
    if resp.GetStatus() != pb.HealthResponse_STATUS_NOT_SERVING {
        t.Fatalf("expected NOT_SERVING, got %v", resp.GetStatus())
    }
}
