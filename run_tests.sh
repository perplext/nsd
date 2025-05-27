#!/bin/bash

# NSD Test Runner Script
# Run all tests with coverage and formatting

set -e

echo "🧪 Running NSD Tests..."
echo "========================="

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to run tests for a package
run_package_tests() {
    local package=$1
    local name=$2
    
    echo -e "\n${YELLOW}Testing ${name}...${NC}"
    if go test -v -race -coverprofile="${package##*/}.coverage" "$package"; then
        echo -e "${GREEN}✓ ${name} tests passed${NC}"
    else
        echo -e "${RED}✗ ${name} tests failed${NC}"
        exit 1
    fi
}

# Clean up previous coverage files
rm -f *.coverage

# Run tests for each package
run_package_tests "./pkg/netcap" "Network Capture"
run_package_tests "./pkg/protocols" "Protocol Analyzers"
run_package_tests "./pkg/security" "Security & Detection"
run_package_tests "./pkg/ui" "UI Components"
run_package_tests "./pkg/utils" "Utilities"
run_package_tests "./pkg/graph" "Graph Components"

# Run integration tests
echo -e "\n${YELLOW}Running Integration Tests...${NC}"
if [ -f "pkg/integration_test.go" ]; then
    if go test -v -race "./pkg" -tags=integration; then
        echo -e "${GREEN}✓ Integration tests passed${NC}"
    else
        echo -e "${RED}✗ Integration tests failed${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}✓ Integration tests skipped (no integration test file)${NC}"
fi

# Combine coverage reports
echo -e "\n${YELLOW}Generating Coverage Report...${NC}"
echo "mode: set" > combined.coverage
tail -q -n +2 *.coverage >> combined.coverage

# Calculate total coverage
total_coverage=$(go tool cover -func=combined.coverage | grep total | awk '{print $3}')
echo -e "Total Coverage: ${GREEN}${total_coverage}${NC}"

# Generate HTML coverage report
go tool cover -html=combined.coverage -o coverage.html
echo -e "HTML coverage report generated: ${GREEN}coverage.html${NC}"

# Run benchmarks (optional)
if [[ "$1" == "--bench" ]]; then
    echo -e "\n${YELLOW}Running Benchmarks...${NC}"
    go test -bench=. -benchmem ./pkg/...
fi

# Run race detector (optional)
if [[ "$1" == "--race" ]]; then
    echo -e "\n${YELLOW}Running Race Detector...${NC}"
    go test -race ./pkg/...
fi

# Clean up individual coverage files
rm -f *.coverage

echo -e "\n${GREEN}✅ All tests completed successfully!${NC}"

# Show test statistics
echo -e "\n${YELLOW}Test Statistics:${NC}"
echo "=================="
go test -cover ./pkg/... | grep -E "ok|FAIL" | column -t

# Check for missing tests
echo -e "\n${YELLOW}Checking for files without tests...${NC}"
for pkg in netcap protocols security ui utils graph; do
    echo -n "Package $pkg: "
    go_files=$(find "./pkg/$pkg" -name "*.go" -not -name "*_test.go" | wc -l)
    test_files=$(find "./pkg/$pkg" -name "*_test.go" | wc -l)
    echo "$go_files source files, $test_files test files"
done

echo -e "\n${GREEN}Test run complete!${NC}"