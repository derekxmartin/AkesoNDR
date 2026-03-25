BINARY_NAME := akeso-ndr
BUILD_DIR   := bin
GO          := go
GOFLAGS     := -v
VERSION     := 0.1.0
LDFLAGS     := -ldflags "-X main.version=$(VERSION)"

# Detect Windows and append .exe
ifeq ($(OS),Windows_NT)
    EXT := .exe
else
    EXT :=
endif

.PHONY: all build test run clean fmt vet lint docker-build docker-up docker-down

all: build

build:
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)$(EXT) ./cmd/akeso-ndr

test:
	$(GO) test $(GOFLAGS) ./...

run: build
	./$(BUILD_DIR)/$(BINARY_NAME)$(EXT)

clean:
	rm -rf $(BUILD_DIR)

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

lint: vet fmt

docker-build:
	docker-compose build

docker-up:
	docker-compose up --build

docker-down:
	docker-compose down
