#!/bin/bash
# Test script to verify cross-platform builds compile successfully

set -e

echo "Testing NSD Cross-Platform Builds"
echo "================================="
echo

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track successes and failures
TOTAL=0
SUCCESS=0
FAILED=0
SKIPPED=0

# Function to test a build
test_build() {
    local os=$1
    local arch=$2
    local extra_flags=$3
    
    TOTAL=$((TOTAL + 1))
    
    echo -n "Building $os/$arch... "
    
    # Set output name
    output="nsd-${os}-${arch}"
    if [ "$os" = "windows" ]; then
        output="${output}.exe"
    fi
    
    # Set environment
    export GOOS=$os
    export GOARCH=$arch
    export CGO_ENABLED=0  # Disable CGO for cross-compilation
    
    # Set extra flags (like GOARM)
    if [ -n "$extra_flags" ]; then
        export $extra_flags
    fi
    
    # Try to build
    if go build -o /tmp/$output ./cmd/nsd 2>/dev/null; then
        echo -e "${GREEN}✓ SUCCESS${NC}"
        SUCCESS=$((SUCCESS + 1))
        rm -f /tmp/$output
    else
        # Some combinations might not be supported
        if [ "$os" = "darwin" ] && [ "$arch" = "386" ]; then
            echo -e "${YELLOW}⊘ SKIPPED${NC} (not supported by Go)"
            SKIPPED=$((SKIPPED + 1))
        else
            echo -e "${RED}✗ FAILED${NC}"
            FAILED=$((FAILED + 1))
        fi
    fi
    
    # Unset extra flags
    if [ -n "$extra_flags" ]; then
        unset ${extra_flags%=*}
    fi
}

# Test all platforms from the Makefile
echo "Testing Linux builds..."
test_build linux amd64
test_build linux 386
test_build linux arm64
test_build linux arm "GOARM=7"
test_build linux arm "GOARM=6"
test_build linux mips
test_build linux mipsle
test_build linux ppc64le
test_build linux s390x

echo
echo "Testing macOS builds..."
test_build darwin amd64
test_build darwin arm64

echo
echo "Testing Windows builds..."
test_build windows amd64
test_build windows 386
test_build windows arm64

echo
echo "Testing BSD builds..."
test_build freebsd amd64
test_build freebsd arm64
test_build freebsd 386
test_build openbsd amd64
test_build openbsd arm64
test_build openbsd 386
test_build netbsd amd64
test_build netbsd arm64
test_build netbsd 386
test_build dragonfly amd64

echo
echo "================================="
echo "Build Test Summary:"
echo "  Total: $TOTAL"
echo -e "  ${GREEN}Success: $SUCCESS${NC}"
if [ $FAILED -gt 0 ]; then
    echo -e "  ${RED}Failed: $FAILED${NC}"
fi
if [ $SKIPPED -gt 0 ]; then
    echo -e "  ${YELLOW}Skipped: $SKIPPED${NC}"
fi

if [ $FAILED -eq 0 ]; then
    echo
    echo -e "${GREEN}All supported platforms build successfully!${NC}"
    exit 0
else
    echo
    echo -e "${RED}Some builds failed. Check the output above.${NC}"
    exit 1
fi