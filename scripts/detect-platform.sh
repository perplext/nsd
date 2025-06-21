#!/bin/bash
# NSD Platform Detection Script
# Helps users determine which NSD build to download

set -e

echo "NSD Platform Detection Script"
echo "============================"
echo

# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Map Darwin to more user-friendly name
if [ "$OS" = "darwin" ]; then
    OS="macos"
fi

# Detect specific Linux distributions
if [ "$OS" = "linux" ]; then
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
    fi
fi

# Map architecture names
case "$ARCH" in
    x86_64|amd64)
        ARCH="amd64"
        ;;
    i386|i686)
        ARCH="386"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        ;;
    armv7l)
        ARCH="armv7"
        ;;
    armv6l)
        ARCH="armv6"
        ;;
    ppc64le)
        ARCH="ppc64le"
        ;;
    s390x)
        ARCH="s390x"
        ;;
    mips)
        # Check endianness
        if [ "$(echo -n I | od -to2 | head -n1 | awk '{print $2}')" = "000111" ]; then
            ARCH="mipsle"
        else
            ARCH="mips"
        fi
        ;;
esac

# Special detection for Raspberry Pi
if [ "$OS" = "linux" ] && [ -f /proc/device-tree/model ]; then
    MODEL=$(tr -d '\0' < /proc/device-tree/model)
    case "$MODEL" in
        *"Raspberry Pi 4"*|*"Raspberry Pi 400"*|*"Raspberry Pi CM4"*)
            if [ "$ARCH" = "arm64" ]; then
                echo "Detected: Raspberry Pi 4/400 (64-bit OS)"
                echo "Recommended build: nsd-linux-arm64"
            else
                echo "Detected: Raspberry Pi 4/400 (32-bit OS)"
                echo "Recommended build: nsd-linux-armv7"
                echo "Note: Consider upgrading to 64-bit OS for better performance"
            fi
            ;;
        *"Raspberry Pi 3"*|*"Raspberry Pi 2"*)
            echo "Detected: $MODEL"
            echo "Recommended build: nsd-linux-armv7"
            ;;
        *"Raspberry Pi Zero"*|*"Raspberry Pi Model"*)
            echo "Detected: $MODEL"
            echo "Recommended build: nsd-linux-armv6"
            ;;
    esac
    echo
fi

# Determine the recommended build
BUILD_NAME="nsd-${OS}-${ARCH}"

echo "System Information:"
echo "  OS: $OS"
echo "  Architecture: $ARCH"
if [ -n "$DISTRO" ]; then
    echo "  Distribution: $DISTRO"
fi
echo

echo "Recommended NSD build: ${BUILD_NAME}"
echo

# Provide download command
LATEST_URL="https://github.com/perplext/nsd/releases/latest/download/${BUILD_NAME}.tar.gz"
if [ "$OS" = "windows" ]; then
    LATEST_URL="https://github.com/perplext/nsd/releases/latest/download/${BUILD_NAME}.zip"
fi

echo "Download command:"
echo "  curl -L ${LATEST_URL} -o ${BUILD_NAME}.tar.gz"
echo
echo "Or visit: https://github.com/perplext/nsd/releases/latest"
echo

# Additional platform-specific notes
case "$OS" in
    linux)
        echo "Don't forget to install libpcap:"
        case "$DISTRO" in
            ubuntu|debian)
                echo "  sudo apt-get install libpcap0.8"
                ;;
            fedora|rhel|centos)
                echo "  sudo yum install libpcap"
                ;;
            arch)
                echo "  sudo pacman -S libpcap"
                ;;
            *)
                echo "  Install libpcap using your distribution's package manager"
                ;;
        esac
        ;;
    freebsd)
        echo "Don't forget to install libpcap:"
        echo "  sudo pkg install libpcap"
        echo
        echo "Note: The pre-built binary has limited functionality."
        echo "For full features, build from source:"
        echo "  sudo pkg install go"
        echo "  git clone https://github.com/perplext/nsd.git"
        echo "  cd nsd && go build -o nsd ./cmd/nsd"
        ;;
    openbsd)
        echo "Don't forget to install libpcap:"
        echo "  doas pkg_add libpcap"
        echo
        echo "Note: The pre-built binary has limited functionality."
        echo "For full features, build from source."
        ;;
    netbsd)
        echo "Don't forget to install libpcap:"
        echo "  sudo pkgin install libpcap"
        ;;
    macos)
        echo "libpcap is included with macOS."
        echo "You may want to update it with Homebrew:"
        echo "  brew install libpcap"
        ;;
esac

echo
echo "Remember: NSD requires root/administrator privileges to capture packets."