#!/bin/bash
set -e

# Variables
BINARY_NAME="nsd"
VERSION=$(git describe --tags --always --dirty | sed 's/^v//')
DESCRIPTION="Network Sniffing Dashboard - Real-time network traffic monitoring tool"
MAINTAINER="NSD Team <nsd@example.com>"
HOMEPAGE="https://github.com/perplext/nsd"

# Create working directory
WORK_DIR="dist/deb-build"
rm -rf "$WORK_DIR"

# Build for both amd64 and arm64
for ARCH in amd64 arm64; do
    echo "Building DEB package for $ARCH..."
    
    # Set up directory structure
    PKG_DIR="$WORK_DIR/${BINARY_NAME}_${VERSION}_${ARCH}"
    mkdir -p "$PKG_DIR/DEBIAN"
    mkdir -p "$PKG_DIR/usr/bin"
    mkdir -p "$PKG_DIR/usr/share/man/man1"
    mkdir -p "$PKG_DIR/usr/share/doc/$BINARY_NAME"
    mkdir -p "$PKG_DIR/usr/share/$BINARY_NAME/examples/i18n"
    
    # Build binary
    echo "Building binary for linux/$ARCH..."
    GOOS=linux GOARCH=$ARCH go build \
        -ldflags="-s -w -X main.version=$VERSION -X main.commit=$(git rev-parse --short HEAD) -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        -o "$PKG_DIR/usr/bin/$BINARY_NAME" ./cmd/nsd
    
    # Copy documentation
    cp README.md "$PKG_DIR/usr/share/doc/$BINARY_NAME/"
    cp LICENSE "$PKG_DIR/usr/share/doc/$BINARY_NAME/"
    
    # Copy examples
    cp -r examples/i18n/* "$PKG_DIR/usr/share/$BINARY_NAME/examples/i18n/"
    cp examples/PLUGINS.md "$PKG_DIR/usr/share/$BINARY_NAME/examples/"
    
    # Create man page
    cat > "$PKG_DIR/usr/share/man/man1/${BINARY_NAME}.1" << EOF
.TH NSD 1 "$(date +%Y-%m-%d)" "$VERSION" "NSD Manual"
.SH NAME
nsd \- Network Sniffing Dashboard
.SH SYNOPSIS
.B nsd
[\fB\-i\fR \fIinterface\fR]
[\fB\-\-theme\fR \fItheme\fR]
[\fB\-\-plugins\fR \fIplugins\fR]
[\fB\-\-help\fR]
.SH DESCRIPTION
NSD is a real-time network traffic monitoring tool with a terminal UI similar to btop. 
It provides visual traffic graphs, connection details, and network statistics using libpcap for packet capture.
.SH OPTIONS
.TP
.BR \-i ", " \-\-interface " " \fIinterface\fR
Network interface to monitor (required)
.TP
.BR \-\-theme " " \fItheme\fR
Color theme to use (default, dark, light, monokai, solarized, nord, dracula)
.TP
.BR \-\-theme\-file " " \fIpath\fR
Path to custom theme JSON/YAML file
.TP
.BR \-\-plugins " " \fIplugins\fR
Comma-separated list of plugin .so files to load
.TP
.BR \-\-i18n\-file " " \fIpath\fR
Path to JSON translation file
.TP
.BR \-h ", " \-\-help
Display help information
.SH EXAMPLES
.TP
Monitor eth0 interface:
.B sudo nsd -i eth0
.TP
Use dark theme:
.B sudo nsd -i eth0 --theme dark
.TP
Load plugins:
.B sudo nsd -i eth0 --plugins /path/to/plugin1.so,/path/to/plugin2.so
.SH KEYBOARD SHORTCUTS
.TP
.B 1-8
Switch between different views
.TP
.B ?
Show help
.TP
.B q
Quit application
.TP
.B p
Pause/resume capture
.TP
.B c
Clear data
.TP
.B f
Set BPF filter
.SH FILES
.TP
.I /usr/share/nsd/examples/
Example files including translations and plugin documentation
.SH NOTES
NSD requires root privileges to capture network packets.
.SH AUTHOR
NSD Team
.SH SEE ALSO
tcpdump(1), wireshark(1), tshark(1)
EOF
    
    gzip -9 "$PKG_DIR/usr/share/man/man1/${BINARY_NAME}.1"
    
    # Create control file
    cat > "$PKG_DIR/DEBIAN/control" << EOF
Package: $BINARY_NAME
Version: $VERSION
Architecture: $ARCH
Maintainer: $MAINTAINER
Homepage: $HOMEPAGE
Description: $DESCRIPTION
 NSD provides real-time network statistics, visual traffic graphs, 
 and connection details using libpcap for packet capture.
 Features include multiple visualization modes, theme support,
 internationalization, and a plugin system.
Depends: libc6, libpcap0.8
Section: net
Priority: optional
EOF
    
    # Create postinst script
    cat > "$PKG_DIR/DEBIAN/postinst" << EOF
#!/bin/sh
set -e

case "\$1" in
    configure)
        # Set capabilities for packet capture without full root
        if command -v setcap >/dev/null 2>&1; then
            setcap cap_net_raw,cap_net_admin+eip /usr/bin/$BINARY_NAME || true
        fi
        ;;
esac

exit 0
EOF
    chmod 755 "$PKG_DIR/DEBIAN/postinst"
    
    # Create postrm script
    cat > "$PKG_DIR/DEBIAN/postrm" << EOF
#!/bin/sh
set -e

case "\$1" in
    remove|purge)
        # Nothing to do
        ;;
esac

exit 0
EOF
    chmod 755 "$PKG_DIR/DEBIAN/postrm"
    
    # Build the package
    dpkg-deb --build "$PKG_DIR" "dist/${BINARY_NAME}_${VERSION}_${ARCH}.deb"
done

# Clean up
rm -rf "$WORK_DIR"

echo "DEB packages created successfully!"