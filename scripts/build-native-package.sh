#!/bin/bash
set -e

# This script builds packages for the current platform only
# For cross-platform builds, use CI/CD or appropriate build environments

# Variables
BINARY_NAME="nsd"
VERSION=$(git describe --tags --always --dirty | sed 's/^v//')
COMMIT=$(git rev-parse --short HEAD)
DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
GOOS=$(go env GOOS)
GOARCH=$(go env GOARCH)

# Create dist directory
mkdir -p dist

echo "Building native package for $GOOS/$GOARCH..."
echo "Version: $VERSION"

# Build binary
echo "Building binary..."
go build \
    -ldflags="-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.date=$DATE" \
    -o "bin/${BINARY_NAME}" ./cmd/nsd

# Create package directory
PKG_DIR="dist/${BINARY_NAME}-${VERSION}-${GOOS}-${GOARCH}"
mkdir -p "$PKG_DIR"

# Copy files
cp "bin/${BINARY_NAME}" "$PKG_DIR/"
cp README.md LICENSE "$PKG_DIR/"

# Create examples directory
mkdir -p "$PKG_DIR/examples"
cp -r examples/i18n "$PKG_DIR/examples/"
cp examples/PLUGINS.md "$PKG_DIR/examples/"

# Create simple man page
mkdir -p "$PKG_DIR/man"
cat > "$PKG_DIR/man/${BINARY_NAME}.1" << EOF
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

# Create install script
cat > "$PKG_DIR/install.sh" << 'EOF'
#!/bin/bash
set -e

BINARY_NAME="nsd"
INSTALL_DIR="/usr/local/bin"
MAN_DIR="/usr/local/share/man/man1"

echo "Installing NSD..."

# Install binary
sudo install -m 755 "$BINARY_NAME" "$INSTALL_DIR/"

# Install man page
if [ -f "man/${BINARY_NAME}.1" ]; then
    sudo mkdir -p "$MAN_DIR"
    sudo install -m 644 "man/${BINARY_NAME}.1" "$MAN_DIR/"
    # Update man database if available
    if command -v mandb >/dev/null 2>&1; then
        sudo mandb >/dev/null 2>&1 || true
    elif command -v makewhatis >/dev/null 2>&1; then
        sudo makewhatis >/dev/null 2>&1 || true
    fi
fi

echo "NSD installed successfully!"
echo "Run 'sudo nsd -i <interface>' to start monitoring"
EOF

chmod +x "$PKG_DIR/install.sh"

# Create the tar.gz
echo "Creating tar.gz archive..."
(cd dist && tar -czf "${BINARY_NAME}-${VERSION}-${GOOS}-${GOARCH}.tar.gz" "${BINARY_NAME}-${VERSION}-${GOOS}-${GOARCH}")

# Create checksum
echo "Creating checksum..."
(cd dist && shasum -a 256 "${BINARY_NAME}-${VERSION}-${GOOS}-${GOARCH}.tar.gz" > "${BINARY_NAME}-${VERSION}-${GOOS}-${GOARCH}.tar.gz.sha256")

# Clean up
rm -rf "$PKG_DIR"

echo ""
echo "Package created successfully!"
echo "  dist/${BINARY_NAME}-${VERSION}-${GOOS}-${GOARCH}.tar.gz"
echo "  dist/${BINARY_NAME}-${VERSION}-${GOOS}-${GOARCH}.tar.gz.sha256"
echo ""
echo "To build for other platforms, use GitHub Actions or set up proper cross-compilation environment."