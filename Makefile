# Makefile for building real_transaction_example for Ubuntu/Linux

.PHONY: build build-linux build-ubuntu clean run test help

# Binary name
BINARY_NAME=real_transaction_example
BINARY_LINUX=$(BINARY_NAME)-linux-amd64
BINARY_UBUNTU=$(BINARY_NAME)-ubuntu

# Main file path
MAIN_FILE=examples/real_transaction_example.go

# Go settings
GO=go
GOFLAGS=-v
LDFLAGS=-s -w

help: ## Display command help
	@echo "Available commands:"
	@echo "  make build          - build for current system"
	@echo "  make build-linux    - build for Linux (amd64)"
	@echo "  make build-ubuntu   - build for Ubuntu (amd64)"
	@echo "  make clean          - clean build files"
	@echo "  make run            - run program"
	@echo "  make test          - run tests"

build: ## build for current system
	@echo "🔨 Building for current system..."
	$(GO) build $(GOFLAGS) -o $(BINARY_NAME) $(MAIN_FILE)
	@echo "✓ Build completed successfully: $(BINARY_NAME)"

build-linux: ## build for Linux (amd64)
	@echo "🔨 Building for Linux (amd64)..."
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY_LINUX) $(MAIN_FILE)
	@echo "✓ Build completed successfully: $(BINARY_LINUX)"
	@echo "📦 File ready for transfer to Ubuntu"

build-ubuntu: build-linux ## build for Ubuntu (same as Linux)
	@echo "✓ File ready for Ubuntu: $(BINARY_LINUX)"

clean: ## clean build files
	@echo "🧹 Cleaning build files..."
	rm -f $(BINARY_NAME) $(BINARY_LINUX) $(BINARY_UBUNTU)
	@echo "✓ Files cleaned"

run: build ## run program
	@echo "🚀 Running program..."
	./$(BINARY_NAME) --maxA 10 --maxB 10

test: ## run tests
	@echo "🧪 Running tests..."
	cd examples && $(GO) test -v -timeout 60s real_transaction_example.go real_transaction_example_test.go

# Build with debug information
build-debug: ## build with debug information
	@echo "🔨 Building with debug information..."
	$(GO) build $(GOFLAGS) -gcflags="-N -l" -o $(BINARY_NAME) $(MAIN_FILE)
	@echo "✓ Build with debug symbols completed"

# Build for different architectures
build-all: ## build for all architectures
	@echo "🔨 Building for all architectures..."
	@mkdir -p dist
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-linux-amd64 $(MAIN_FILE)
	GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-linux-arm64 $(MAIN_FILE)
	@echo "✓ Build for all architectures completed"


