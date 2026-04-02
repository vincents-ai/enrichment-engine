BINARY_NAME := enrich
BUILD_DIR := ./bin
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.Version=$(VERSION)

.PHONY: all build test test-all test-unit test-integration test-behavioral test-scenario lint fmt clean

all: lint test build

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/enrich

test: test-unit test-integration test-behavioral

test-unit:
	CGO_ENABLED=0 go test ./pkg/...

test-integration:
	CGO_ENABLED=0 go test ./test/integration/...

test-behavioral:
	CGO_ENABLED=0 GODOG=1 go test ./test/behavioral/...

test-scenario:
	CGO_ENABLED=0 go test -tags integration ./test/scenario/...

test-all: test test-scenario

lint:
	CGO_ENABLED=0 golangci-lint run ./...

fmt:
	CGO_ENABLED=0 gofmt -w .
	CGO_ENABLED=0 goimports -local github.com/shift/enrichment-engine -w .

clean:
	rm -rf $(BUILD_DIR)
