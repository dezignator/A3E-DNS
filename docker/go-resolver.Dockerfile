# docker/go-resolver.Dockerfile
#
# Go resolver image. Multi-stage build: the builder compiles a static
# binary, the runtime stage is a minimal distroless image.
#
# We used distroless rather than alpine because the resolver has no
# shell-scripted entrypoint and no runtime debugging that would have
# justified the extra ~5 MB of a shell; distroless produces a ~12 MB
# image that can be scanned cleanly for CVEs.

ARG GO_VERSION=1.21

# ------------------------------------------------------------------ #
# Build stage
# ------------------------------------------------------------------ #
FROM golang:${GO_VERSION}-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.31.0 \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0

WORKDIR /build
COPY proto /build/proto
COPY go/a3e_resolver /build/go/a3e_resolver

WORKDIR /build/go/a3e_resolver

RUN mkdir -p internal/api/pb \
    && protoc \
        --go_out=internal/api/pb \
        --go_opt=paths=source_relative \
        --go-grpc_out=internal/api/pb \
        --go-grpc_opt=paths=source_relative \
        -I /build/proto \
        /build/proto/a3e/v1/*.proto \
    && go mod download \
    && CGO_ENABLED=0 go build \
        -trimpath \
        -ldflags="-s -w" \
        -o /out/a3e-resolver \
        ./cmd/server

# ------------------------------------------------------------------ #
# Runtime stage
# ------------------------------------------------------------------ #
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=builder /out/a3e-resolver /usr/local/bin/a3e-resolver

USER nonroot:nonroot

EXPOSE 8053 9090

ENTRYPOINT ["/usr/local/bin/a3e-resolver"]
CMD ["--config", "/etc/a3e-resolver/config.yaml"]
