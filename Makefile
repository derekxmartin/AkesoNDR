BINARY_NAME := akeso-ndr
BUILD_DIR   := bin
GO          := go
GOFLAGS     := -v
VERSION     := 0.1.0
LDFLAGS     := -ldflags "-X main.version=$(VERSION)"

.PHONY: all build test run clean fmt vet lint

all: build

build:
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/akeso-ndr

test:
	$(GO) test $(GOFLAGS) ./...

run: build
	./$(BUILD_DIR)/$(BINARY_NAME)

clean:
	rm -rf $(BUILD_DIR)

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

lint: vet fmt
