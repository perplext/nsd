# NSD - Network Sniffing Dashboard
[![CI](https://github.com/user/nsd/actions/workflows/ci.yml/badge.svg)](https://github.com/user/nsd/actions/workflows/ci.yml)

A cross-platform network sniffing dashboard with a terminal UI similar to btop. NSD allows users to view network statistics and drill down into individual connections.

## UI Preview

Check out the `docs/ui_preview.txt` file for a preview of the terminal UI, including the network traffic visualization graphs.

## Features

- Real-time network traffic statistics
- Visual graphs for network traffic ingress and egress
- Static gradient shading for graph fills (toggleable via `--gradient` flag)
- Custom theme loading from JSON/YAML via `--theme-file` flag
- Detailed connection information (source, destination, protocol, etc.)
- Interactive terminal UI with btop-like look and feel
- Promiscuous mode for capturing all network traffic
- Cross-platform support (Linux, macOS, Windows)

## Requirements

- Go 1.18 or higher
- libpcap development files (for packet capture)
  - On Ubuntu/Debian: `sudo apt-get install libpcap-dev`
  - On macOS: Included with the OS or install via Homebrew: `brew install libpcap`
  - On Windows: Install [npcap](https://npcap.com/) or [WinPcap](https://www.winpcap.org/)

## Installation

```bash
# Clone the repository
git clone https://github.com/user/nsd.git
cd nsd

# Build the application
go build -o nsd ./cmd/nsd
# Or use make
make build

# Build for all platforms
make build-all

# Run the application (requires root/administrator privileges)
sudo ./bin/nsd
```

## Usage

```bash
# Basic usage
sudo nsd

# Specify a network interface
sudo ./nsd -i eth0

# Specify a theme
sudo ./nsd -theme "High-Contrast Dark"

# Disable static gradient shading
sudo ./nsd -gradient=false

# Load custom theme
sudo ./nsd --theme-file /path/to/custom_theme.json

# Help information
./nsd -h
```

## Plugin System

NSD can load Go-based plugins at runtime using the `--plugins` flag. Plugins must be compiled as Go plugins (.so) with:

```bash
cd examples/simpleplugin
go build -buildmode=plugin -o simpleplugin.so simpleplugin.go
```

Then start NSD with your plugin:

```bash
sudo ./nsd --plugins examples/simpleplugin/simpleplugin.so
```

The provided `SimplePlugin` logs the packet buffer length every 10 seconds.

## Protocol Filtering & Charting

NSD supports live protocol-level filtering and usage charting:
- Press `b` to set a BPF filter (e.g. `tcp and port 80`) during capture.
- Press `p` to view and auto-refresh the raw packet buffer.
- The protocol usage panel on the right shows a real-time breakdown (%) of observed protocols with horizontal bars.
- Press `h` to view a packet-size histogram.
- Press `d` to view HTTP/DNS packet counts.
- Press `g` to view remote IP geo-mapping.

## Localization

NSD supports localization of CLI messages and UI labels via JSON translation files. Use the `--i18n-file` flag to load translations:

```bash
sudo ./nsd --i18n-file /path/to/translations.json
```

Your JSON file should map message keys to translated strings, for example:

```json
{
  "requires_root": "Ce programme nécessite des privilèges root pour capturer des paquets.",
  "run_as_root": "Exécutez avec sudo ou en tant qu'administrateur."
}
```

Unrecognized keys fall back to the original English text.

## Security and Ethics

This tool is designed for network administrators and security professionals to monitor networks they own or have explicit permission to monitor. Always ensure you have proper authorization before monitoring any network.

**WARNING**: Unauthorized network monitoring may be illegal in many jurisdictions and violate privacy laws.

## Testing

Run unit tests:

```bash
go test ./pkg/netcap
```

## Continuous Integration

We use GitHub Actions to build and test NSD on Linux, macOS, and Windows. The CI workflow is defined in [.github/workflows/ci.yml](.github/workflows/ci.yml).

## License

MIT
