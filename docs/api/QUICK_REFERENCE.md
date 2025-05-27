# NSD API Quick Reference

## Core Components

### Network Monitoring

```go
import "github.com/user/nsd/pkg/netcap"

// Create monitor
monitor := netcap.NewNetworkMonitor()
defer monitor.StopAllCaptures()

// Set filter
monitor.SetBPFFilter("tcp port 443")

// Start capture
err := monitor.StartCapture("eth0")

// Get stats
stats := monitor.GetStats()
connections := monitor.GetConnections()
```

### User Interface

```go
import "github.com/user/nsd/pkg/ui"

// Create UI
ui := ui.NewUI(monitor).
    SetTheme("Dark+").
    SetStyle("Rounded")

// Run UI
err := ui.Run()
```

### Security

```go
import "github.com/user/nsd/pkg/security"

// Validate inputs
validator := security.NewValidator()
err := validator.ValidateInterfaceName("eth0")
err := validator.ValidateBPFFilter("tcp port 80")

// Drop privileges
pm := security.NewPrivilegeManager()
err := pm.DropPrivileges("nobody")
```

### Error Handling

```go
import "github.com/user/nsd/pkg/errors"

// Create errors
err := errors.NewNetworkError("eth0", "capture", err)

// Check retryable
if errors.IsRetryable(err) {
    // Retry operation
}
```

### Rate Limiting

```go
import "github.com/user/nsd/pkg/ratelimit"

// Create limiter
limiter := ratelimit.NewRateLimiter(config)

// Check limits
if limiter.AllowPacket(size) {
    // Process packet
}
```

### Resource Control

```go
import "github.com/user/nsd/pkg/resource"

// Create controller
controller := resource.NewController(512, 50.0)

// Start monitoring
controller.StartMonitoring(time.Second)

// Check resources
err := controller.CheckResources()
```

## Common Patterns

### Basic Network Monitor

```go
func main() {
    monitor := netcap.NewNetworkMonitor()
    defer monitor.StopAllCaptures()
    
    if err := monitor.StartCapture("eth0"); err != nil {
        log.Fatal(err)
    }
    
    ui := ui.NewUI(monitor)
    if err := ui.Run(); err != nil {
        log.Fatal(err)
    }
}
```

### Secure Monitor with Validation

```go
func main() {
    validator := security.NewValidator()
    
    // Validate interface
    iface := "eth0"
    if err := validator.ValidateInterfaceName(iface); err != nil {
        log.Fatal(err)
    }
    
    // Create monitor
    monitor := netcap.NewNetworkMonitor()
    monitor.SetBPFFilter("tcp")
    
    // Start capture
    if err := monitor.StartCapture(iface); err != nil {
        log.Fatal(err)
    }
    
    // Drop privileges
    pm := security.NewPrivilegeManager()
    pm.DropPrivileges("nobody")
    
    // Run UI
    ui := ui.NewUI(monitor)
    ui.Run()
}
```

### Plugin Development

```go
package main

import "github.com/user/nsd/pkg/plugin"

type MyPlugin struct {
    monitor *netcap.NetworkMonitor
}

func (p *MyPlugin) Name() string { return "MyPlugin" }
func (p *MyPlugin) Init(m *netcap.NetworkMonitor) error {
    p.monitor = m
    return nil
}
func (p *MyPlugin) Stop() error { return nil }

var Plugin plugin.Plugin = &MyPlugin{}
```

### Custom Visualization

```go
type CustomViz struct{}

func (v *CustomViz) Name() string { return "Custom" }
func (v *CustomViz) Description() string { return "Custom viz" }
func (v *CustomViz) GetMinSize() (int, int) { return 40, 10 }
func (v *CustomViz) Update(m *netcap.NetworkMonitor) {}
func (v *CustomViz) Render(data interface{}) string {
    return "Visualization output"
}
```

## Data Types

### Connection

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

### Stats Map

```go
stats := monitor.GetStats()
// Keys: TotalPackets, TotalBytes, PacketsPerSecond, 
//       BytesPerSecond, ActiveConnections, TopProtocols
```

### Theme

```go
type Theme struct {
    Name       string
    Foreground string
    Background string
    Border     string
    Title      string
    Info       string
    Warning    string
    Error      string
    Success    string
    Primary    string
    Secondary  string
    Tertiary   string
    Quaternary string
}
```

## Command Line Flags

```bash
# Network capture
-i <interface>      # Network interface
-filter <expr>      # BPF filter

# UI options
-theme <name>       # UI theme
-style <name>       # Border style
-gradient           # Enable gradients

# Security
-drop-privileges    # Drop privileges
-user <name>        # User to run as

# Export
-export-svg <file>  # Export to SVG
-export-png <file>  # Export to PNG

# Plugins
-plugins <files>    # Load plugins

# i18n
-i18n-file <file>  # Load translations
```

## Error Types

```go
// Network errors
errors.NewNetworkError(iface, operation, err)

// UI errors  
errors.NewUIError(component, operation, err)

// Config errors
errors.NewConfigError(field, value, err)
```

## Available Themes

- Dark+
- Light
- Monokai
- Solarized
- Nord
- Dracula
- OneDark
- GruvboxDark
- CyberpunkNeon
- Matrix
- Midnight
- Synthwave

## Available Border Styles

- Standard
- Rounded
- Double
- ASCII
- Minimal
- Heavy
- Dashed
- Neon
- Tech
- Vintage

## Keyboard Shortcuts

- `Tab` - Navigate
- `Enter` - Select
- `Esc` - Back
- `q` - Quit
- `f` - Fullscreen
- `p` - Pause
- `r` - Reset
- `s` - Screenshot
- `h`/`?` - Help
- `1-9` - Switch viz