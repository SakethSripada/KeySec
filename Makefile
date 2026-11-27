VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test lint install clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/keysec ./cmd/keysec

test:
	go test -race ./...

lint:
	go vet ./...
	golangci-lint run

install:
	go install -ldflags "$(LDFLAGS)" ./cmd/keysec

clean:
	rm -rf bin dist
