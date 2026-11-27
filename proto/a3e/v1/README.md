# A3E-DNS wire contract

This directory contains the protobuf definitions for the A3E-DNS
resolver–pipeline interface. The public contract lives in `a3e.proto`;
the internal pipeline messages live in `pipeline.proto`.

## Versioning

The package version is part of the import path (`a3e.v1`). Any change
that is not wire-compatible bumps the version. The resolver negotiates
the version at connection setup through the standard gRPC mechanism;
a resolver built against `a3e.v1` refuses to connect to a pipeline
serving `a3e.v2`.

## Building the Go bindings

```bash
protoc \
  --go_out=go/a3e_resolver/internal/api/pb \
  --go_opt=paths=source_relative \
  --go-grpc_out=go/a3e_resolver/internal/api/pb \
  --go-grpc_opt=paths=source_relative \
  proto/a3e/v1/*.proto
