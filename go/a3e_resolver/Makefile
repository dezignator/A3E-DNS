# go/a3e_resolver/Makefile
#
# Build targets for the A3E-DNS resolver. The `proto` target
# regenerates the protobuf bindings; the `build` target produces a
# static binary; the `test` target runs the unit tests.

BINARY := bin/a3e-resolver
GO := go
PROTOC := protoc
PROTO_DIR := ../../proto/a3e/v1
PB_OUT := internal/api/pb

.PHONY: all build test clean proto lint fmt

all: build

build:
	$(GO) build -trimpath -ldflags="-s -w -X main.buildVersion=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)" -o $(BINARY) ./cmd/server

test:
	$(GO) test -race -count=1 ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

proto:
	mkdir -p $(PB_OUT)
	$(PROTOC) \
		--go_out=$(PB_OUT) \
		--go_opt=paths=source_relative \
		--go-grpc_out=$(PB_OUT) \
		--go-grpc_opt=paths=source_relative \
		-I ../../proto \
		$(PROTO_DIR)/*.proto

clean:
	rm -rf bin $(PB_OUT)/*.go

vet:
	$(GO) vet ./...
