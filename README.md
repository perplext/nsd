# NetMon - Network Traffic Monitor

A cross-platform network traffic monitoring tool with a terminal UI similar to btop. NetMon allows users to view network statistics and drill down into individual connections.

## UI Preview

Check out the `docs/ui_preview.txt` file for a preview of the terminal UI, including the network traffic visualization graphs.

## Features

- Real-time network traffic statistics
- Visual graphs for network traffic ingress and egress
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
git clone https://github.com/user/netmon.git
cd netmon

# Build the application
go build -o netmon

# Run the application (requires root/administrator privileges)
sudo ./netmon
```

## Usage

```bash
# Basic usage
sudo ./netmon

# Specify a network interface
sudo ./netmon -i eth0

# Help information
./netmon -h
```

## Protocol Filtering & Charting

NetMon supports live protocol-level filtering and usage charting:
- Press `b` to set a BPF filter (e.g. `tcp and port 80`) during capture.
- Press `p` to view and auto-refresh the raw packet buffer.
- The protocol usage panel on the right shows a real-time breakdown (%) of observed protocols with horizontal bars.
- Press `h` to view a packet-size histogram.
- Press `d` to view HTTP/DNS packet counts.
- Press `g` to view remote IP geo-mapping.

## Security and Ethics

This tool is designed for network administrators and security professionals to monitor networks they own or have explicit permission to monitor. Always ensure you have proper authorization before monitoring any network.

**WARNING**: Unauthorized network monitoring may be illegal in many jurisdictions and violate privacy laws.

## Testing

Run unit tests:

```bash
go test ./pkg/netcap
```

## License

MIT
