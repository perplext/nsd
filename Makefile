.PHONY: build clean run all

# Default target
all: build

# Build the application
build:
	@echo "Building NetMon..."
	@go build -o bin/netmon ./cmd/netmon

# Build for multiple platforms
build-all: clean
	@echo "Building for multiple platforms..."
	@mkdir -p bin
	@echo "Building for Linux..."
	@GOOS=linux GOARCH=amd64 go build -o bin/netmon-linux-amd64 ./cmd/netmon
	@echo "Building for macOS..."
	@GOOS=darwin GOARCH=amd64 go build -o bin/netmon-darwin-amd64 ./cmd/netmon
	@echo "Building for Windows..."
	@GOOS=windows GOARCH=amd64 go build -o bin/netmon-windows-amd64.exe ./cmd/netmon

# Run the application
run: build
	@echo "Running NetMon (requires root/admin privileges)..."
	@sudo ./bin/netmon

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf bin/

# Install dependencies
deps:
	@echo "Installing dependencies..."
	@go get -u github.com/google/gopacket
	@go get -u github.com/gdamore/tcell/v2
	@go get -u github.com/rivo/tview

# Run tests
test:
	@echo "Running tests..."
	@go test -v ./...

# Show help
help:
	@echo "Available targets:"
	@echo "  all       - Build the application (default)"
	@echo "  build     - Build for the current platform"
	@echo "  build-all - Build for multiple platforms"
	@echo "  run       - Build and run the application"
	@echo "  clean     - Remove build artifacts"
	@echo "  deps      - Install dependencies"
	@echo "  test      - Run tests"
	@echo "  help      - Show this help message"
