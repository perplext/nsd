# NSD Architecture Documentation

## Overview

NSD (Network Sniffing Dashboard) follows a modular architecture designed for extensibility, performance, and maintainability. The application is built using Go and consists of several core packages that work together to provide real-time network monitoring capabilities.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        NSD Application                       │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Web UI    │  │   TUI App   │  │    CLI Tools        │  │
│  │  (Browser)  │  │ (Terminal)  │  │ (i18n-scaffold)     │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  REST API   │  │   WebSocket │  │    Plugin System    │  │
│  │   Server    │  │   Handler   │  │     (.so files)     │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Alerts    │  │  Recording  │  │   Visualization     │  │
│  │  & Notifs   │  │  & Replay   │  │     Components      │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  Protocol   │  │  Security   │  │      I18N           │  │
│  │  Analyzers  │  │  & Threat   │  │   Localization      │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Network   │  │    Graph    │  │       Utils         │  │
│  │   Capture   │  │ Components  │  │    & Helpers        │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                     System Layer                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   libpcap   │  │   tcell/    │  │    HTTP Server      │  │
│  │  (gopacket) │  │    tview    │  │   (gorilla/mux)     │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Network Capture Layer (`pkg/netcap`)

The network capture layer is responsible for low-level packet capture and initial processing.

**Key Components:**
- `NetworkMonitor`: Main capture coordinator
- `CaptureEngine`: Handles libpcap integration
- `PacketProcessor`: Initial packet filtering and parsing
- `InterfaceManager`: Network interface discovery and management

**Data Flow:**
```
Network Interface → libpcap → gopacket → PacketProcessor → Statistics Engine
                                     ↓
                            Protocol Analyzers → Connection Tracker
```

### 2. User Interface Layer (`pkg/ui`)

Provides multiple interface options for different use cases.

**Terminal UI Components:**
- `TUI`: Main terminal interface controller
- `Dashboard`: Layout manager for different views
- `Theme`: Customizable styling system
- `Visualization`: Charts, graphs, and data displays

**Web UI Components:**
- Static HTML/CSS/JavaScript dashboard
- Real-time WebSocket updates
- RESTful API endpoints

### 3. Protocol Analysis (`pkg/protocols`)

Specialized analyzers for different network protocols.

**Supported Protocols:**
- HTTP/HTTPS analysis
- DNS query tracking  
- SSH/SFTP monitoring
- FTP/FTPS analysis
- SMTP/IMAP/POP3 email protocols
- IRC communication
- SCP file transfers

### 4. Security & Threat Detection (`pkg/security`)

Advanced security features for network monitoring.

**Components:**
- Input validation and sanitization
- Privilege management and dropping
- Threat detection engines (Snort, Suricata, YARA, Zeek)
- Network attack detection
- Unified detection pipeline

### 5. Plugin System (`pkg/plugin`)

Extensible plugin architecture for custom functionality.

**Plugin Interface:**
```go
type Plugin interface {
    Init(nm *netcap.NetworkMonitor) error
    Name() string
}

type UIHandler interface {
    GetDescription() string
    GetOutput() []string
}
```

### 6. Recording & Replay (`pkg/recording`)

Traffic capture and analysis replay capabilities.

**Features:**
- PCAP file generation
- JSON statistics recording
- Configurable compression
- Playback with timing control

### 7. Alert System (`pkg/alerts`)

Configurable alerting and notification framework.

**Notification Channels:**
- Email (SMTP)
- Webhooks (HTTP POST)
- Console logging
- Custom channel plugins

## Data Flow Architecture

### Real-time Monitoring Flow

```
1. Network Interface
   ↓ (Raw packets)
2. libpcap Capture
   ↓ (Packet data)
3. gopacket Parsing
   ↓ (Structured packets)
4. Protocol Analysis
   ↓ (Protocol-specific data)
5. Statistics Aggregation
   ↓ (Metrics & counters)
6. UI Updates
   ├─ Terminal UI (tview)
   ├─ Web Dashboard (WebSocket)
   └─ API Endpoints (HTTP)
```

### Plugin Integration Flow

```
1. Plugin Loading (.so files)
   ↓
2. Plugin Initialization
   ↓
3. Monitor Registration
   ↓
4. Event Processing
   ├─ Packet Events
   ├─ Statistics Events
   └─ UI Events
   ↓
5. Plugin Output
   └─ UI Integration
```

## Configuration Management

### Configuration Sources (Priority Order)
1. Command-line flags
2. Environment variables
3. Configuration files (`~/.config/nsd/`, `/etc/nsd/`)
4. Default values

### Theme System
- Built-in themes (Dark+, Light, Monokai, etc.)
- Custom JSON/YAML theme files
- Runtime theme switching
- Auto-detection based on terminal

### Internationalization
- JSON translation files
- Runtime language switching
- 34+ supported languages
- Fallback to English

## Security Architecture

### Privilege Model
```
1. Start as root/admin (required for packet capture)
2. Initialize capture interfaces
3. Drop privileges to unprivileged user
4. Continue operation with minimal permissions
```

### Input Validation
- Interface name validation
- BPF filter validation
- File path sanitization
- Network input validation

### Security Features
- Capability-based privileges (Linux)
- Input sanitization
- Rate limiting
- Resource controls

## Performance Considerations

### Optimization Strategies
1. **Packet Processing:**
   - Zero-copy packet handling where possible
   - Efficient BPF filtering at kernel level
   - Lock-free data structures for statistics

2. **Memory Management:**
   - Bounded packet buffers
   - Configurable retention periods
   - Garbage collection tuning

3. **UI Performance:**
   - Throttled update rates
   - Efficient chart rendering
   - Minimal DOM manipulation (Web UI)

4. **Concurrent Processing:**
   - Separate goroutines for capture, analysis, and UI
   - Channel-based communication
   - Non-blocking operations

## Error Handling

### Error Categories
1. **Initialization Errors:** Interface access, privilege issues
2. **Runtime Errors:** Packet loss, processing failures
3. **Configuration Errors:** Invalid settings, file access
4. **Network Errors:** Interface down, permission changes

### Recovery Strategies
- Automatic retry mechanisms
- Graceful degradation
- Error reporting and logging
- Resource cleanup on failure

## Testing Architecture

### Test Categories
1. **Unit Tests:** Individual component testing
2. **Integration Tests:** Component interaction testing
3. **Performance Tests:** Benchmarking and profiling
4. **Security Tests:** Privilege and input validation testing

### Mock Components
- Mock network interfaces
- Mock packet sources
- Mock security engines
- Mock UI components

## Deployment Architecture

### Installation Methods
1. **Binary Distribution:** Direct executable download
2. **Package Managers:** 
   - Snap (Ubuntu/Linux)
   - Chocolatey (Windows)
   - AUR (Arch Linux)
3. **Container Images:** Docker/Podman support
4. **Source Build:** Go toolchain compilation

### Runtime Requirements
- **Linux:** libpcap, elevated privileges
- **Windows:** WinPcap/Npcap, administrator access
- **macOS:** System packet capture permissions

## Extension Points

### Plugin Development
- Go plugin architecture
- C/C++ plugin support (via CGO)
- Custom protocol analyzers
- UI extensions

### Theme Development
- JSON/YAML theme definitions
- CSS-like styling system
- Custom visualization components

### Protocol Extensions
- Custom protocol analyzers
- Deep packet inspection modules
- Application-specific monitoring

This architecture provides a solid foundation for network monitoring while maintaining flexibility for future enhancements and customization.