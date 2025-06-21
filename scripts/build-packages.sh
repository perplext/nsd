#!/bin/bash
set -e

# Variables
BINARY_NAME="nsd"
VERSION=$(git describe --tags --always --dirty | sed 's/^v//')
COMMIT=$(git rev-parse --short HEAD)
DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
DESCRIPTION="Network Sniffing Dashboard - Real-time network traffic monitoring tool"
MAINTAINER="NSD Team <nsd@example.com>"
ARCH_MAP=("amd64:amd64" "arm64:arm64")

# Create dist directory
mkdir -p dist

echo "Building packages for version $VERSION..."

# Function to build binary
build_binary() {
    local goos=$1
    local goarch=$2
    local output=$3
    
    echo "Building $goos/$goarch..."
    
    # For cross-compilation with CGO dependencies, we need special handling
    if [ "$goos" = "$(go env GOOS)" ] && [ "$goarch" = "$(go env GOARCH)" ]; then
        # Native build
        go build \
            -ldflags="-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.date=$DATE" \
            -o "$output" ./cmd/nsd
    else
        # Cross-compilation - disable CGO for now
        # Note: This means pcap functionality won't work in cross-compiled binaries
        # For production, you'd need proper cross-compilation toolchain
        echo "Warning: Cross-compiling with CGO_ENABLED=0 - pcap functionality will be limited"
        CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build \
            -ldflags="-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.date=$DATE" \
            -o "$output" ./cmd/nsd || {
            echo "Cross-compilation failed for $goos/$goarch"
            return 1
        }
    fi
}

# Build Linux packages
for arch_pair in "${ARCH_MAP[@]}"; do
    IFS=':' read -r goarch pkgarch <<< "$arch_pair"
    
    # Build binary
    build_binary "linux" "$goarch" "bin/${BINARY_NAME}-linux-${goarch}"
    
    # Create tar.gz archive
    echo "Creating Linux tar.gz for $goarch..."
    mkdir -p "dist/${BINARY_NAME}-${VERSION}-linux-${goarch}"
    cp "bin/${BINARY_NAME}-linux-${goarch}" "dist/${BINARY_NAME}-${VERSION}-linux-${goarch}/${BINARY_NAME}"
    cp README.md LICENSE "dist/${BINARY_NAME}-${VERSION}-linux-${goarch}/"
    
    # Create examples directory
    mkdir -p "dist/${BINARY_NAME}-${VERSION}-linux-${goarch}/examples"
    cp -r examples/i18n "dist/${BINARY_NAME}-${VERSION}-linux-${goarch}/examples/"
    cp examples/PLUGINS.md "dist/${BINARY_NAME}-${VERSION}-linux-${goarch}/examples/"
    
    # Create man page (basic)
    mkdir -p "dist/${BINARY_NAME}-${VERSION}-linux-${goarch}/man"
    cat > "dist/${BINARY_NAME}-${VERSION}-linux-${goarch}/man/${BINARY_NAME}.1" << EOF
.TH NSD 1 "$DATE" "$VERSION" "NSD Manual"
.SH NAME
nsd \- Network Sniffing Dashboard
.SH SYNOPSIS
.B nsd
[\fB\-i\fR \fIinterface\fR]
[\fB\-\-theme\fR \fItheme\fR]
[\fB\-\-plugins\fR \fIplugins\fR]
.SH DESCRIPTION
NSD is a real-time network traffic monitoring tool with a terminal UI similar to btop.
.SH OPTIONS
.TP
.BR \-i ", " \-\-interface " " \fIinterface\fR
Network interface to monitor
.TP
.BR \-\-theme " " \fItheme\fR
Color theme to use
.TP
.BR \-\-plugins " " \fIplugins\fR
Comma-separated list of plugin .so files to load
.SH AUTHOR
NSD Team
.SH SEE ALSO
tcpdump(1), wireshark(1)
EOF
    
    # Create the tar.gz
    (cd dist && tar -czf "${BINARY_NAME}-${VERSION}-linux-${goarch}.tar.gz" "${BINARY_NAME}-${VERSION}-linux-${goarch}")
    rm -rf "dist/${BINARY_NAME}-${VERSION}-linux-${goarch}"
done

# Build macOS packages
for arch_pair in "${ARCH_MAP[@]}"; do
    IFS=':' read -r goarch pkgarch <<< "$arch_pair"
    
    # Build binary
    build_binary "darwin" "$goarch" "bin/${BINARY_NAME}-darwin-${goarch}"
    
    # Create tar.gz archive
    echo "Creating macOS tar.gz for $goarch..."
    mkdir -p "dist/${BINARY_NAME}-${VERSION}-darwin-${goarch}"
    cp "bin/${BINARY_NAME}-darwin-${goarch}" "dist/${BINARY_NAME}-${VERSION}-darwin-${goarch}/${BINARY_NAME}"
    cp README.md LICENSE "dist/${BINARY_NAME}-${VERSION}-darwin-${goarch}/"
    
    # Create examples directory
    mkdir -p "dist/${BINARY_NAME}-${VERSION}-darwin-${goarch}/examples"
    cp -r examples/i18n "dist/${BINARY_NAME}-${VERSION}-darwin-${goarch}/examples/"
    cp examples/PLUGINS.md "dist/${BINARY_NAME}-${VERSION}-darwin-${goarch}/examples/"
    
    # Create the tar.gz
    (cd dist && tar -czf "${BINARY_NAME}-${VERSION}-darwin-${goarch}.tar.gz" "${BINARY_NAME}-${VERSION}-darwin-${goarch}")
    rm -rf "dist/${BINARY_NAME}-${VERSION}-darwin-${goarch}"
done

# Create checksums
echo "Creating checksums..."
(cd dist && sha256sum *.tar.gz > SHA256SUMS)

# Create a simple install script
cat > dist/install.sh << 'EOF'
#!/bin/bash
set -e

BINARY_NAME="nsd"
INSTALL_DIR="/usr/local/bin"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case $ARCH in
    x86_64)
        ARCH="amd64"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

case $OS in
    linux|darwin)
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

# Extract version from filename
VERSION=$(ls ${BINARY_NAME}-*-${OS}-${ARCH}.tar.gz | sed -E "s/${BINARY_NAME}-(.+)-${OS}-${ARCH}.tar.gz/\1/")
ARCHIVE="${BINARY_NAME}-${VERSION}-${OS}-${ARCH}.tar.gz"

if [ ! -f "$ARCHIVE" ]; then
    echo "Archive not found: $ARCHIVE"
    exit 1
fi

echo "Installing NSD ${VERSION} for ${OS}/${ARCH}..."

# Extract archive
tar -xzf "$ARCHIVE"

# Install binary
sudo install -m 755 "${BINARY_NAME}-${VERSION}-${OS}-${ARCH}/${BINARY_NAME}" "$INSTALL_DIR/"

# Install man page if on Linux
if [ "$OS" = "linux" ] && [ -f "${BINARY_NAME}-${VERSION}-${OS}-${ARCH}/man/${BINARY_NAME}.1" ]; then
    sudo mkdir -p /usr/local/share/man/man1
    sudo install -m 644 "${BINARY_NAME}-${VERSION}-${OS}-${ARCH}/man/${BINARY_NAME}.1" /usr/local/share/man/man1/
    sudo mandb >/dev/null 2>&1 || true
fi

# Cleanup
rm -rf "${BINARY_NAME}-${VERSION}-${OS}-${ARCH}"

echo "NSD installed successfully!"
echo "Run 'sudo nsd -i <interface>' to start monitoring"
EOF

chmod +x dist/install.sh

echo "Package building complete!"
echo "Files created in dist/:"
ls -la dist/