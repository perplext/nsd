# Platform-Specific Installation Guide

This guide provides installation instructions for all supported platforms.

## Table of Contents

- [Linux](#linux)
  - [Standard Linux (x86_64/amd64)](#standard-linux-x86_64amd64)
  - [Raspberry Pi](#raspberry-pi)
  - [Other ARM Devices](#other-arm-devices)
  - [MIPS Routers](#mips-routers)
- [BSD Systems](#bsd-systems)
  - [FreeBSD](#freebsd)
  - [OpenBSD](#openbsd)
  - [NetBSD](#netbsd)
  - [DragonFlyBSD](#dragonflybsd)
- [macOS](#macos)
- [Windows](#windows)

## Linux

### Standard Linux (x86_64/amd64)

Most modern Linux distributions on standard PCs:

```bash
# Download and extract
curl -L https://github.com/perplext/nsd/releases/latest/download/nsd-linux-amd64.tar.gz | tar xz

# Install libpcap (if not already installed)
# Debian/Ubuntu:
sudo apt-get install libpcap0.8

# RHEL/CentOS/Fedora:
sudo yum install libpcap

# Arch Linux:
sudo pacman -S libpcap

# Run
sudo ./nsd
```

### Raspberry Pi

#### Raspberry Pi 4 (64-bit OS)
```bash
# Download ARM64 version
curl -L https://github.com/perplext/nsd/releases/latest/download/nsd-linux-arm64.tar.gz | tar xz

# Install dependencies
sudo apt-get update
sudo apt-get install libpcap0.8

# Run
sudo ./nsd
```

#### Raspberry Pi 2/3 (32-bit OS)
```bash
# Download ARMv7 version
curl -L https://github.com/perplext/nsd/releases/latest/download/nsd-linux-armv7.tar.gz | tar xz

# Install dependencies
sudo apt-get update
sudo apt-get install libpcap0.8

# Run
sudo ./nsd
```

#### Raspberry Pi Zero/1
```bash
# Download ARMv6 version
curl -L https://github.com/perplext/nsd/releases/latest/download/nsd-linux-armv6.tar.gz | tar xz

# Install dependencies
sudo apt-get update
sudo apt-get install libpcap0.8

# Run
sudo ./nsd
```

### Other ARM Devices

For other ARM-based devices (Orange Pi, ODROID, etc.), choose the appropriate version:
- ARM64 devices: `nsd-linux-arm64.tar.gz`
- 32-bit ARMv7 devices: `nsd-linux-armv7.tar.gz`
- Older ARM devices: `nsd-linux-armv6.tar.gz`

### MIPS Routers

For routers running OpenWrt or similar:

```bash
# For big-endian MIPS (most routers)
wget https://github.com/perplext/nsd/releases/latest/download/nsd-linux-mips.tar.gz

# For little-endian MIPS
wget https://github.com/perplext/nsd/releases/latest/download/nsd-linux-mipsle.tar.gz

# Extract
tar -xzf nsd-linux-mips*.tar.gz

# Note: These are cross-compiled builds with limited functionality
# For full features, build from source on your router
```

### Other Architectures

- **PowerPC (ppc64le)**: IBM POWER servers - `nsd-linux-ppc64le.tar.gz`
- **s390x**: IBM Z mainframes - `nsd-linux-s390x.tar.gz`
- **i386**: 32-bit x86 systems - `nsd-linux-386.tar.gz`

## BSD Systems

### FreeBSD

```bash
# Install dependencies
sudo pkg install libpcap go

# Option 1: Download pre-built binary
fetch https://github.com/perplext/nsd/releases/latest/download/nsd-freebsd-amd64.tar.gz
tar -xzf nsd-freebsd-amd64.tar.gz

# Option 2: Build from source (recommended)
git clone https://github.com/perplext/nsd.git
cd nsd
go build -o nsd ./cmd/nsd

# Run with root privileges
sudo ./nsd
```

For ARM64 FreeBSD (on Raspberry Pi or similar):
```bash
fetch https://github.com/perplext/nsd/releases/latest/download/nsd-freebsd-arm64.tar.gz
```

### OpenBSD

```bash
# Install dependencies
doas pkg_add libpcap go

# Option 1: Download pre-built binary
ftp https://github.com/perplext/nsd/releases/latest/download/nsd-openbsd-amd64.tar.gz
tar -xzf nsd-openbsd-amd64.tar.gz

# Option 2: Build from source (recommended)
git clone https://github.com/perplext/nsd.git
cd nsd
go build -o nsd ./cmd/nsd

# Run with root privileges
doas ./nsd
```

### NetBSD

```bash
# Install dependencies
sudo pkgin install libpcap go

# Download appropriate version
ftp https://github.com/perplext/nsd/releases/latest/download/nsd-netbsd-amd64.tar.gz
tar -xzf nsd-netbsd-amd64.tar.gz

# Run
sudo ./nsd
```

### DragonFlyBSD

```bash
# Install dependencies
sudo pkg install libpcap go

# Download
fetch https://github.com/perplext/nsd/releases/latest/download/nsd-dragonfly-amd64.tar.gz
tar -xzf nsd-dragonfly-amd64.tar.gz

# Run
sudo ./nsd
```

## macOS

See the main [README](../README.md#installation) for macOS installation instructions.

## Windows

See the dedicated [Windows Installation Guide](WINDOWS.md) for detailed instructions.

## Building from Source

For any platform, you can build from source if pre-built binaries don't work:

```bash
# Install Go 1.24+ and libpcap for your platform
git clone https://github.com/perplext/nsd.git
cd nsd
go build -o nsd ./cmd/nsd
```

## Troubleshooting

### "Library not found" errors
Install libpcap for your platform using the appropriate package manager.

### "Permission denied" errors
NSD requires root/administrator privileges for packet capture.

### Cross-compiled builds have limited functionality
The BSD and some Linux ARM/MIPS builds are cross-compiled with CGO disabled. For full functionality, build from source on your target platform.

### Performance on Low-Power Devices
On devices like Raspberry Pi Zero or MIPS routers:
- Use BPF filters to reduce packet processing: `nsd -filter "port 80 or port 443"`
- Limit the number of connections tracked
- Consider monitoring specific interfaces only

## Platform Support Matrix

| Platform | Architecture | Native Build | Cross-Compiled | Full Features |
|----------|-------------|--------------|----------------|---------------|
| Linux | amd64 | ✓ | - | ✓ |
| Linux | 386 | ✓ | - | ✓ |
| Linux | arm64 | - | ✓ | Limited |
| Linux | armv7 | - | ✓ | Limited |
| Linux | armv6 | - | ✓ | Limited |
| Linux | mips/mipsle | - | ✓ | Limited |
| Linux | ppc64le | - | ✓ | Limited |
| Linux | s390x | - | ✓ | Limited |
| macOS | amd64 | ✓ | - | ✓ |
| macOS | arm64 | ✓ | - | ✓ |
| Windows | amd64 | ✓ | - | ✓ |
| Windows | 386 | ✓ | - | ✓ |
| Windows | arm64 | - | ✓ | Limited |
| FreeBSD | amd64/arm64/386 | - | ✓ | Limited |
| OpenBSD | amd64/arm64/386 | - | ✓ | Limited |
| NetBSD | amd64/arm64/386 | - | ✓ | Limited |
| DragonFlyBSD | amd64 | - | ✓ | Limited |

**Note**: "Limited" functionality means the binary works but packet capture features may be restricted due to CGO being disabled in cross-compilation.