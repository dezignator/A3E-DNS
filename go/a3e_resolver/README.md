# a3e-resolver — Go resolver service

This directory contains the Go resolver that fronts the A3E-DNS Python
pipeline. It is what a deployment operator would run: a small gRPC
service that classifies DNS queries through the pipeline and exposes
Prometheus metrics for the surrounding observability stack.

## Why Go

The reference DoH, DoT and DoQ resolvers — AdGuard Home, CoreDNS,
dnsproxy — are all written in Go. Deploying the A3E-DNS pipeline behind
one of them is the natural integration path, and writing the resolver
in the same language as those tools means it can be dropped into their
existing build and deployment pipelines without a runtime dependency
mismatch.

## Structure

| Package | Purpose |
|---------|---------|
| `cmd/server` | Command entry point |
| `internal/api` | gRPC service implementation |
| `internal/api/pb` | Generated protobuf bindings |
| `internal/pipeline` | Client for the Python pipeline |
| `internal/metrics` | Prometheus exporters |
| `internal/config` | YAML configuration loader |

## Building

```bash
make proto   # regenerate protobuf bindings
make build   # produce bin/a3e-resolver
make test    # run the unit tests
