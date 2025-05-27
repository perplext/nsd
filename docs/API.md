# NSD API Documentation

## Overview

NSD provides a comprehensive API for network traffic monitoring, packet capture, and visualization. This document covers all public interfaces, structs, and methods available for developers.

## Table of Contents

1. [Network Capture API](#network-capture-api)
2. [UI API](#ui-api)
3. [Graph API](#graph-api)
4. [Plugin API](#plugin-api)
5. [Security API](#security-api)
6. [Error Handling API](#error-handling-api)
7. [Rate Limiting API](#rate-limiting-api)
8. [Resource Control API](#resource-control-api)

## Network Capture API

### Package: `github.com/user/nsd/pkg/netcap`

The netcap package provides network packet capture and monitoring functionality.

#### NetworkMonitor

The main interface for network traffic monitoring.

```go
type NetworkMonitor struct {
    Interfaces     map[string]*InterfaceStats
    ActiveHandles  map[string]*pcap.Handle
    StopCapture    chan bool
    // ... private fields
}
```

##### Constructor

```go
func NewNetworkMonitor() *NetworkMonitor
```
Creates a new NetworkMonitor instance.

**Returns:**
- `*NetworkMonitor`: A new network monitor instance

**Example:**
```go
monitor := netcap.NewNetworkMonitor()
```

##### Methods

###### StartCapture

```go
func (nm *NetworkMonitor) StartCapture(interfaceName string) error
```
Starts packet capture on the specified network interface.

**Parameters:**
- `interfaceName`: Name of the network interface (e.g., "eth0", "wlan0")

**Returns:**
- `error`: Error if capture cannot be started

**Example:**
```go
err := monitor.StartCapture("eth0")
if err != nil {
    log.Fatal(err)
}
```

###### SetBPFFilter

```go
func (nm *NetworkMonitor) SetBPFFilter(filter string)
```
Sets a BPF (Berkeley Packet Filter) expression for filtering captured packets.

**Parameters:**
- `filter`: BPF filter expression (e.g., "tcp port 80")

**Example:**
```go
monitor.SetBPFFilter("tcp port 443 or tcp port 80")
```

###### StopAllCaptures

```go
func (nm *NetworkMonitor) StopAllCaptures()
```
Stops all active packet captures and closes handles.

**Example:**
```go
defer monitor.StopAllCaptures()
```

###### GetStats

```go
func (nm *NetworkMonitor) GetStats() map[string]interface{}
```
Returns current network statistics.

**Returns:**
- `map[string]interface{}`: Statistics including packet counts, byte counts, and connection information

**Example:**
```go
stats := monitor.GetStats()
fmt.Printf("Total packets: %v\n", stats["TotalPackets"])
```

###### GetConnections

```go
func (nm *NetworkMonitor) GetConnections() map[ConnectionKey]*Connection
```
Returns all active network connections.

**Returns:**
- `map[ConnectionKey]*Connection`: Map of active connections

#### Connection

Represents a network connection.

```go
type Connection struct {
    SrcIP    net.IP
    DstIP    net.IP
    SrcPort  uint16
    DstPort  uint16
    Protocol string
    Service  string
    Size     uint64
    Packets  uint64
    LastSeen time.Time
}
```

#### InterfaceStats

Contains statistics for a network interface.

```go
type InterfaceStats struct {
    Name        string
    BytesIn     uint64
    BytesOut    uint64
    PacketsIn   uint64
    PacketsOut  uint64
    Connections map[ConnectionKey]*Connection
}
```

#### Helper Functions

```go
func GetInterfaces() ([]pcap.Interface, error)
```
Returns a list of available network interfaces.

**Returns:**
- `[]pcap.Interface`: List of network interfaces
- `error`: Error if interfaces cannot be enumerated

## UI API

### Package: `github.com/user/nsd/pkg/ui`

The ui package provides terminal user interface components and visualization.

#### UI

The main user interface controller.

```go
type UI struct {
    // ... private fields
}
```

##### Constructor

```go
func NewUI(monitor *netcap.NetworkMonitor) *UI
```
Creates a new UI instance.

**Parameters:**
- `monitor`: NetworkMonitor instance to display data from

**Returns:**
- `*UI`: New UI instance

##### Methods

###### SetTheme

```go
func (ui *UI) SetTheme(themeName string) *UI
```
Sets the UI theme.

**Parameters:**
- `themeName`: Name of the theme (e.g., "Dark+", "Light", "Monokai")

**Returns:**
- `*UI`: UI instance for method chaining

**Example:**
```go
ui := ui.NewUI(monitor).SetTheme("Dark+")
```

###### SetStyle

```go
func (ui *UI) SetStyle(styleName string) *UI
```
Sets the border style.

**Parameters:**
- `styleName`: Border style name (e.g., "Standard", "Rounded", "Double")

**Returns:**
- `*UI`: UI instance for method chaining

###### Run

```go
func (ui *UI) Run() error
```
Starts the UI event loop. This method blocks until the UI is closed.

**Returns:**
- `error`: Error if UI cannot be started

###### Stop

```go
func (ui *UI) Stop()
```
Stops the UI and exits the event loop.

###### ExportSVG

```go
func (ui *UI) ExportSVG(filename string) error
```
Exports the current visualization as an SVG file.

**Parameters:**
- `filename`: Path to save the SVG file

**Returns:**
- `error`: Error if export fails

###### RegisterPlugin

```go
func (ui *UI) RegisterPlugin(name, description string)
```
Registers a plugin with the UI.

**Parameters:**
- `name`: Plugin name
- `description`: Plugin description

#### Theme Management

```go
func LoadThemes(filename string) error
```
Loads custom themes from a JSON or YAML file.

**Parameters:**
- `filename`: Path to theme file

**Returns:**
- `error`: Error if themes cannot be loaded

```go
func ExportTheme(themeName, filename string) error
```
Exports a theme to a file.

**Parameters:**
- `themeName`: Name of theme to export
- `filename`: Path to save theme file

**Returns:**
- `error`: Error if export fails

## Graph API

### Package: `github.com/user/nsd/pkg/graph`

The graph package provides data visualization components.

#### Graph

Represents a graph visualization.

```go
type Graph struct {
    Data      []float64
    MaxValue  float64
    Title     string
    Color     string
    Style     GraphStyle
    // ... private fields
}
```

##### Constructor

```go
func NewGraph(width, height int) *Graph
```
Creates a new graph.

**Parameters:**
- `width`: Graph width in characters
- `height`: Graph height in characters

**Returns:**
- `*Graph`: New graph instance

##### Methods

###### AddDataPoint

```go
func (g *Graph) AddDataPoint(value float64)
```
Adds a data point to the graph.

**Parameters:**
- `value`: Data value to add

###### Render

```go
func (g *Graph) Render() string
```
Renders the graph as a string.

**Returns:**
- `string`: Rendered graph

#### GraphStyle

```go
type GraphStyle int

const (
    Braille GraphStyle = iota
    Block
    TTY
)
```

## Plugin API

### Package: `github.com/user/nsd/pkg/plugin`

The plugin package provides interfaces for extending NSD functionality.

#### Plugin Interface

All plugins must implement this interface.

```go
type Plugin interface {
    Name() string
    Init(monitor *netcap.NetworkMonitor) error
    Stop() error
}
```

##### Methods

###### Name

```go
Name() string
```
Returns the plugin name.

**Returns:**
- `string`: Plugin name

###### Init

```go
Init(monitor *netcap.NetworkMonitor) error
```
Initializes the plugin with a network monitor instance.

**Parameters:**
- `monitor`: NetworkMonitor instance

**Returns:**
- `error`: Error if initialization fails

###### Stop

```go
Stop() error
```
Stops the plugin and cleans up resources.

**Returns:**
- `error`: Error if stop fails

#### UIHandler Interface

Optional interface for plugins that provide UI output.

```go
type UIHandler interface {
    GetDescription() string
    GetOutput() []string
}
```

#### Loading Plugins

```go
func Load(filename string) (Plugin, error)
```
Loads a plugin from a .so file.

**Parameters:**
- `filename`: Path to plugin file

**Returns:**
- `Plugin`: Loaded plugin instance
- `error`: Error if loading fails

## Security API

### Package: `github.com/user/nsd/pkg/security`

The security package provides input validation and security controls.

#### Validator

Provides input validation methods.

```go
type Validator struct {
    // ... private fields
}
```

##### Constructor

```go
func NewValidator() *Validator
```
Creates a new validator instance.

##### Methods

###### ValidateInterfaceName

```go
func (v *Validator) ValidateInterfaceName(name string) error
```
Validates a network interface name.

**Parameters:**
- `name`: Interface name to validate

**Returns:**
- `error`: Error if validation fails

###### ValidateBPFFilter

```go
func (v *Validator) ValidateBPFFilter(filter string) error
```
Validates a BPF filter expression.

**Parameters:**
- `filter`: BPF filter to validate

**Returns:**
- `error`: Error if validation fails

###### ValidateFilePath

```go
func (v *Validator) ValidateFilePath(path string) error
```
Validates a file path.

**Parameters:**
- `path`: File path to validate

**Returns:**
- `error`: Error if validation fails

#### PrivilegeManager

Manages privilege separation.

```go
type PrivilegeManager struct {
    // ... private fields
}
```

##### Constructor

```go
func NewPrivilegeManager() *PrivilegeManager
```
Creates a new privilege manager.

##### Methods

###### DropPrivileges

```go
func (pm *PrivilegeManager) DropPrivileges(username string) error
```
Drops root privileges to the specified user.

**Parameters:**
- `username`: User to drop privileges to

**Returns:**
- `error`: Error if privileges cannot be dropped

## Error Handling API

### Package: `github.com/user/nsd/pkg/errors`

The errors package provides custom error types and error handling utilities.

#### Error Types

```go
type NetworkError struct {
    Interface string
    Operation string
    Err       error
}

type UIError struct {
    Component string
    Operation string
    Err       error
}

type ConfigError struct {
    Field string
    Value interface{}
    Err   error
}
```

#### Error Creation Functions

```go
func NewNetworkError(iface, op string, err error) *NetworkError
```
Creates a new network error.

```go
func NewUIError(component, op string, err error) *UIError
```
Creates a new UI error.

```go
func NewConfigError(field string, value interface{}, err error) *ConfigError
```
Creates a new configuration error.

#### Error Wrapping

```go
func WrapNetworkError(iface, op string, err error) error
```
Wraps an error with network context.

```go
func WrapUIError(component, op string, err error) error
```
Wraps an error with UI context.

#### Retry Logic

```go
func IsRetryable(err error) bool
```
Determines if an error is retryable.

**Parameters:**
- `err`: Error to check

**Returns:**
- `bool`: True if the error is retryable

## Rate Limiting API

### Package: `github.com/user/nsd/pkg/ratelimit`

The ratelimit package provides rate limiting functionality.

#### RateLimiter

Controls packet processing rates.

```go
type RateLimiter struct {
    // ... private fields
}
```

##### Constructor

```go
func NewRateLimiter(config Config) *RateLimiter
```
Creates a new rate limiter.

**Parameters:**
- `config`: Rate limiter configuration

**Returns:**
- `*RateLimiter`: New rate limiter instance

##### Methods

###### AllowPacket

```go
func (rl *RateLimiter) AllowPacket(size int) bool
```
Checks if a packet should be processed.

**Parameters:**
- `size`: Packet size in bytes

**Returns:**
- `bool`: True if packet should be processed

###### AllowConnection

```go
func (rl *RateLimiter) AllowConnection() bool
```
Checks if a new connection should be tracked.

**Returns:**
- `bool`: True if connection should be tracked

###### SetAdaptiveMode

```go
func (rl *RateLimiter) SetAdaptiveMode(enabled bool)
```
Enables or disables adaptive rate limiting.

**Parameters:**
- `enabled`: Whether adaptive mode is enabled

## Resource Control API

### Package: `github.com/user/nsd/pkg/resource`

The resource package provides system resource monitoring and control.

#### Controller

Manages system resource usage.

```go
type Controller struct {
    // ... private fields
}
```

##### Constructor

```go
func NewController(maxMemoryMB int64, maxCPUPercent float64) *Controller
```
Creates a new resource controller.

**Parameters:**
- `maxMemoryMB`: Maximum memory usage in MB
- `maxCPUPercent`: Maximum CPU usage percentage

**Returns:**
- `*Controller`: New controller instance

##### Methods

###### CheckResources

```go
func (c *Controller) CheckResources() error
```
Checks if resource limits are exceeded.

**Returns:**
- `error`: Error if limits are exceeded

###### StartMonitoring

```go
func (c *Controller) StartMonitoring(interval time.Duration)
```
Starts resource monitoring.

**Parameters:**
- `interval`: Check interval

###### GetStats

```go
func (c *Controller) GetStats() ResourceStats
```
Returns current resource statistics.

**Returns:**
- `ResourceStats`: Current resource usage

#### ResourceStats

```go
type ResourceStats struct {
    MemoryUsageMB   int64
    CPUPercent      float64
    GoroutineCount  int
    ThrottleActive  bool
    EmergencyMode   bool
}
```

## Example Usage

### Basic Network Monitoring

```go
package main

import (
    "fmt"
    "log"
    "time"
    
    "github.com/user/nsd/pkg/netcap"
    "github.com/user/nsd/pkg/ui"
)

func main() {
    // Create network monitor
    monitor := netcap.NewNetworkMonitor()
    
    // Start capture on eth0
    err := monitor.StartCapture("eth0")
    if err != nil {
        log.Fatal(err)
    }
    defer monitor.StopAllCaptures()
    
    // Create and run UI
    ui := ui.NewUI(monitor).SetTheme("Dark+")
    
    // Run UI in goroutine
    go func() {
        if err := ui.Run(); err != nil {
            log.Fatal(err)
        }
    }()
    
    // Print stats every 5 seconds
    ticker := time.NewTicker(5 * time.Second)
    for range ticker.C {
        stats := monitor.GetStats()
        fmt.Printf("Packets: %v, Bytes: %v\n", 
            stats["TotalPackets"], 
            stats["TotalBytes"])
    }
}
```

### Creating a Plugin

```go
package main

import (
    "github.com/user/nsd/pkg/netcap"
    "github.com/user/nsd/pkg/plugin"
)

type MyPlugin struct {
    monitor *netcap.NetworkMonitor
    output  []string
}

func (p *MyPlugin) Name() string {
    return "MyPlugin"
}

func (p *MyPlugin) Init(monitor *netcap.NetworkMonitor) error {
    p.monitor = monitor
    // Initialize plugin
    return nil
}

func (p *MyPlugin) Stop() error {
    // Cleanup
    return nil
}

func (p *MyPlugin) GetDescription() string {
    return "My custom NSD plugin"
}

func (p *MyPlugin) GetOutput() []string {
    return p.output
}

// Exported variable required for plugin loading
var Plugin plugin.Plugin = &MyPlugin{}
```

### Secure Network Monitoring

```go
package main

import (
    "log"
    
    "github.com/user/nsd/pkg/netcap"
    "github.com/user/nsd/pkg/security"
)

func main() {
    // Create validator
    validator := security.NewValidator()
    
    // Validate inputs
    interfaceName := "eth0"
    if err := validator.ValidateInterfaceName(interfaceName); err != nil {
        log.Fatal("Invalid interface name:", err)
    }
    
    filter := "tcp port 443"
    if err := validator.ValidateBPFFilter(filter); err != nil {
        log.Fatal("Invalid BPF filter:", err)
    }
    
    // Create secure monitor
    monitor := netcap.NewNetworkMonitor()
    monitor.SetBPFFilter(filter)
    
    // Start capture
    if err := monitor.StartCapture(interfaceName); err != nil {
        log.Fatal(err)
    }
    
    // Drop privileges
    pm := security.NewPrivilegeManager()
    if err := pm.DropPrivileges("nobody"); err != nil {
        log.Printf("Warning: Could not drop privileges: %v", err)
    }
    
    // Continue monitoring...
}
```

## Error Handling Best Practices

1. Always check returned errors
2. Use custom error types for context
3. Implement retry logic for transient errors
4. Log errors with appropriate context

```go
err := monitor.StartCapture("eth0")
if err != nil {
    if errors.IsRetryable(err) {
        // Retry logic
        for i := 0; i < 3; i++ {
            time.Sleep(time.Second * time.Duration(i+1))
            err = monitor.StartCapture("eth0")
            if err == nil {
                break
            }
        }
    }
    if err != nil {
        log.Fatal("Failed to start capture:", err)
    }
}
```

## Thread Safety

Most NSD APIs are thread-safe and can be called concurrently. The following packages provide thread-safe operations:

- `netcap`: All methods are thread-safe
- `ui`: UI methods must be called from the main goroutine
- `plugin`: Plugin methods are thread-safe
- `security`: All validation methods are thread-safe
- `ratelimit`: All methods are thread-safe
- `resource`: All methods are thread-safe

## Performance Considerations

1. **Packet Capture**: Use BPF filters to reduce packet processing overhead
2. **Rate Limiting**: Enable rate limiting for high-traffic environments
3. **Resource Control**: Set appropriate memory and CPU limits
4. **UI Updates**: Limit UI refresh rate to reduce CPU usage

## Versioning

NSD follows semantic versioning (SemVer):
- MAJOR version for incompatible API changes
- MINOR version for backwards-compatible functionality
- PATCH version for backwards-compatible bug fixes

Current version: 1.0.0

## Support

For API support and questions:
- GitHub Issues: https://github.com/user/nsd/issues
- Documentation: https://nsd.example.com/docs
- Examples: See `/examples` directory in the repository