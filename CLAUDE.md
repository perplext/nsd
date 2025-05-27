# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

NSD (Network Sniffing Dashboard) is a cross-platform network traffic monitoring tool with a terminal UI similar to btop. It provides real-time network statistics, visual traffic graphs, and connection details using libpcap for packet capture.

## Common Development Commands

```bash
# Build the binary
make build              # Builds to bin/nsd

# Build for all platforms (Linux, macOS, Windows)
make build-all

# Run the application (requires root/admin privileges)
make run               # or: sudo ./bin/nsd

# Run tests
make test              # or: go test -v ./...

# Install dependencies
make deps

# Clean build artifacts
make clean
```

## Architecture

The codebase follows a standard Go project structure with packages organized by functionality:

- **cmd/nsd**: Main application entry point that initializes the TUI and starts packet capture
- **pkg/netcap**: Network capture layer using gopacket/libpcap for packet analysis and traffic monitoring
- **pkg/ui**: Terminal UI implementation using tview/tcell with support for:
  - Multiple visualization modes (graphs, tables, histograms)
  - Theme system (built-in themes + custom JSON/YAML)
  - Internationalization (i18n) support
- **pkg/graph**: Graph visualization components for rendering network traffic data
- **pkg/plugin**: Plugin system allowing dynamic loading of Go plugins (.so files)
- **pkg/utils**: Shared utilities for formatting and data processing

## Key Technical Details

1. **Packet Capture**: Uses libpcap through gopacket, requires root/admin privileges
2. **UI Framework**: Built on tview/tcell for cross-platform terminal UI
3. **Plugin System**: Supports loading external Go plugins via `--plugins` flag
4. **Theme Support**: Themes can be customized via JSON/YAML files in the themes directory
5. **I18n**: Translations loaded via `--i18n-file`, with examples in examples/i18n/
6. **BPF Filtering**: Supports Berkeley Packet Filter expressions for traffic filtering

## Testing

The project has test files for all major packages. Run tests with `make test` or `go test -v ./...`. No linter is currently configured in the Makefile.

## Important Notes

- Always run with root/admin privileges due to packet capture requirements
- When modifying UI components, check theme compatibility
- Plugin development examples available in examples/simpleplugin/
- The application supports both promiscuous and non-promiscuous capture modes