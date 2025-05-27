.PHONY: all build build-all clean run test test-integration test-coverage benchmark lint security deps install help

# Variables
BINARY_NAME := nsd
VERSION := $(shell git describe --tags --always --dirty)
COMMIT := $(shell git rev-parse --short HEAD)
DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -ldflags="-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

# Default target
all: lint test build

# Build the application
build:
	@echo "Building NSD..."
	@go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/nsd

# Build for multiple platforms
build-all: clean
	@echo "Building for multiple platforms..."
	@mkdir -p bin
	@echo "Building for Linux AMD64..."
	@GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64 ./cmd/nsd
	@echo "Building for Linux ARM64..."
	@GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-arm64 ./cmd/nsd
	@echo "Building for macOS AMD64..."
	@GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-amd64 ./cmd/nsd
	@echo "Building for macOS ARM64..."
	@GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-arm64 ./cmd/nsd
	@echo "Building for Windows AMD64..."
	@GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-windows-amd64.exe ./cmd/nsd

# Run the application
run: build
	@echo "Running NSD (requires root/admin privileges)..."
	@sudo ./bin/$(BINARY_NAME)

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf bin/
	@rm -rf coverage/
	@rm -f coverage.out
	@rm -f benchmark.txt

# Install dependencies
deps:
	@echo "Installing dependencies..."
	@go mod download
	@go mod tidy

# Install the binary
install: build
	@echo "Installing NSD..."
	@sudo cp bin/$(BINARY_NAME) /usr/local/bin/
	@sudo chmod +x /usr/local/bin/$(BINARY_NAME)

# Run tests
test:
	@echo "Running tests..."
	@go test -v -race ./...

# Run integration tests
test-integration:
	@echo "Running integration tests..."
	@sudo -E go test -v -race -tags=integration ./test/integration/...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	@mkdir -p coverage
	@go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	@go tool cover -html=coverage.out -o coverage/coverage.html
	@echo "Coverage report generated at coverage/coverage.html"

# Run benchmarks
benchmark:
	@echo "Running benchmarks..."
	@go test -bench=. -benchmem -run=^$ ./... | tee benchmark.txt

# Run linters
lint:
	@echo "Running linters..."
	@if command -v golangci-lint >/dev/null; then \
		golangci-lint run --timeout=5m; \
	else \
		echo "golangci-lint not installed. Install with:"; \
		echo "  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin"; \
		exit 1; \
	fi

# Run security checks
security:
	@echo "Running security checks..."
	@if command -v gosec >/dev/null; then \
		gosec -fmt=sarif -out=gosec-results.sarif ./...; \
	else \
		echo "gosec not installed. Install with: go install github.com/securego/gosec/v2/cmd/gosec@latest"; \
	fi
	@if command -v govulncheck >/dev/null; then \
		govulncheck ./...; \
	else \
		echo "govulncheck not installed. Install with: go install golang.org/x/vuln/cmd/govulncheck@latest"; \
	fi

# Generate mocks
mocks:
	@echo "Generating mocks..."
	@go generate ./...

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@goimports -w .

# Docker build
docker:
	@echo "Building Docker image..."
	@docker build -t $(BINARY_NAME):$(VERSION) .

# Release build
release: clean
	@echo "Building release artifacts..."
	@mkdir -p dist
	@$(MAKE) build-all
	@cd bin && for file in *; do \
		if [[ "$$file" == *.exe ]]; then \
			zip "../dist/$$file.zip" "$$file"; \
		else \
			tar -czf "../dist/$$file.tar.gz" "$$file"; \
		fi; \
	done
	@echo "Release artifacts created in dist/"

# Show version
version:
	@echo "NSD version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Build date: $(DATE)"

# Show help
help:
	@echo "NSD (Network Sniffing Dashboard) Makefile"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all              - Run lint, test, and build (default)"
	@echo "  build            - Build for the current platform"
	@echo "  build-all        - Build for all supported platforms"
	@echo "  run              - Build and run the application"
	@echo "  clean            - Remove build artifacts"
	@echo "  deps             - Install dependencies"
	@echo "  install          - Install binary to /usr/local/bin"
	@echo "  test             - Run unit tests"
	@echo "  test-integration - Run integration tests (requires root)"
	@echo "  test-coverage    - Run tests with coverage report"
	@echo "  benchmark        - Run benchmarks"
	@echo "  lint             - Run linters"
	@echo "  security         - Run security checks"
	@echo "  mocks            - Generate mocks"
	@echo "  fmt              - Format code"
	@echo "  docker           - Build Docker image"
	@echo "  release          - Build release artifacts"
	@echo "  version          - Show version information"
	@echo "  help             - Show this help message"
