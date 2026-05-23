GO      ?= go
BIN_DIR ?= bin

.PHONY: all build server client test fmt vet clean

all: build

build: server client

server:
	$(GO) build -o $(BIN_DIR)/d8a-server ./cmd/server

client:
	$(GO) build -o $(BIN_DIR)/d8a-client ./cmd/client

test:
	$(GO) test ./...

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

clean:
	rm -rf $(BIN_DIR)
