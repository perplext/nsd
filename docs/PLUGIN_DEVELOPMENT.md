# NSD Plugin Development Guide

This guide covers how to develop custom plugins for NSD (Network Sniffing Dashboard) to extend its functionality.

## Table of Contents

1. [Plugin System Overview](#plugin-system-overview)
2. [Plugin Interface](#plugin-interface)
3. [Development Environment Setup](#development-environment-setup)
4. [Creating Your First Plugin](#creating-your-first-plugin)
5. [Advanced Plugin Features](#advanced-plugin-features)
6. [Best Practices](#best-practices)
7. [Testing and Debugging](#testing-and-debugging)
8. [Plugin Examples](#plugin-examples)
9. [Distribution and Deployment](#distribution-and-deployment)

## Plugin System Overview

NSD uses Go's plugin system to dynamically load shared objects (`.so` files) at runtime. Plugins can:

- Monitor network traffic and statistics
- Implement custom protocol analyzers
- Integrate with external systems
- Provide custom visualizations
- Send alerts and notifications
- Extend the UI with custom components

### Plugin Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    NSD Core Application                 │
├─────────────────────────────────────────────────────────┤
│                      Plugin Manager                     │
├─────────────────────────────────────────────────────────┤
│   Plugin 1    │   Plugin 2    │   Plugin 3    │  ...   │
│  (Protocol)   │  (Alerting)   │   (Custom)    │        │
└─────────────────────────────────────────────────────────┘
```

## Plugin Interface

### Core Plugin Interface

All plugins must implement the `Plugin` interface:

```go
package main

import "github.com/perplext/nsd/pkg/netcap"

type Plugin interface {
    // Init is called once when the plugin is loaded
    // nm provides access to the NetworkMonitor instance
    Init(nm *netcap.NetworkMonitor) error
    
    // Name returns the plugin's display name
    Name() string
}
```

### Optional UI Integration

For UI integration, implement the `UIHandler` interface:

```go
type UIHandler interface {
    // GetDescription returns a description of the plugin
    GetDescription() string
    
    // GetOutput returns the current output/status of the plugin
    // This will be displayed in the plugin view (press 'G' in TUI)
    GetOutput() []string
}
```

### Optional Lifecycle Management

For cleanup operations, implement the `Lifecycle` interface:

```go
type Lifecycle interface {
    // Stop is called when the plugin should clean up resources
    Stop() error
    
    // Restart is called when the plugin should restart
    Restart() error
}
```

## Development Environment Setup

### Prerequisites

1. **Go Environment:**
   ```bash
   go version  # Should be 1.19 or later
   ```

2. **NSD Development Dependencies:**
   ```bash
   # Clone NSD repository for development
   git clone https://github.com/perplext/nsd.git
   cd nsd
   
   # Install dependencies
   go mod download
   ```

3. **Required Packages:**
   ```bash
   # Linux
   sudo apt-get install libpcap-dev build-essential
   
   # macOS
   brew install libpcap
   
   # Windows (with MSYS2)
   pacman -S mingw-w64-x86_64-libpcap
   ```

### Plugin Project Structure

```
my-nsd-plugin/
├── go.mod
├── go.sum
├── main.go                 # Plugin implementation
├── README.md              # Plugin documentation
├── examples/              # Usage examples
│   └── config.json
├── tests/                 # Plugin tests
│   └── main_test.go
└── Makefile              # Build automation
```

### Initialize Plugin Project

```bash
mkdir my-nsd-plugin
cd my-nsd-plugin

# Initialize Go module
go mod init my-nsd-plugin

# Add NSD dependency
go mod edit -require github.com/perplext/nsd@latest
go mod tidy
```

## Creating Your First Plugin

### Basic Plugin Template

Create `main.go`:

```go
package main

import (
    "fmt"
    "log"
    "sync"
    "time"

    "github.com/perplext/nsd/pkg/netcap"
    "github.com/perplext/nsd/pkg/plugin"
)

// MyPlugin implements the Plugin interface
type MyPlugin struct {
    monitor     *netcap.NetworkMonitor
    output      []string
    mutex       sync.RWMutex
    stopChan    chan bool
    isRunning   bool
}

// Name returns the plugin name
func (p *MyPlugin) Name() string {
    return "My First Plugin"
}

// Init initializes the plugin
func (p *MyPlugin) Init(nm *netcap.NetworkMonitor) error {
    p.monitor = nm
    p.output = make([]string, 0)
    p.stopChan = make(chan bool)
    
    log.Printf("Plugin %s initialized", p.Name())
    
    // Start background worker
    go p.worker()
    
    return nil
}

// GetDescription returns plugin description (UIHandler interface)
func (p *MyPlugin) GetDescription() string {
    return "A simple example plugin that monitors packet statistics"
}

// GetOutput returns current plugin output (UIHandler interface)
func (p *MyPlugin) GetOutput() []string {
    p.mutex.RLock()
    defer p.mutex.RUnlock()
    
    // Return copy of output
    output := make([]string, len(p.output))
    copy(output, p.output)
    return output
}

// Stop cleans up plugin resources (Lifecycle interface)
func (p *MyPlugin) Stop() error {
    if p.isRunning {
        close(p.stopChan)
        p.isRunning = false
    }
    return nil
}

// worker runs in background and monitors network statistics
func (p *MyPlugin) worker() {
    p.isRunning = true
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            p.updateStats()
        case <-p.stopChan:
            return
        }
    }
}

// updateStats fetches current network statistics
func (p *MyPlugin) updateStats() {
    if p.monitor == nil {
        return
    }
    
    stats := p.monitor.GetStats()
    
    p.mutex.Lock()
    defer p.mutex.Unlock()
    
    // Add new output line
    line := fmt.Sprintf("[%s] Packets: %v, Bytes: %v", 
        time.Now().Format("15:04:05"),
        stats["TotalPackets"],
        stats["TotalBytes"],
    )
    
    p.output = append(p.output, line)
    
    // Keep only last 50 lines
    if len(p.output) > 50 {
        p.output = p.output[len(p.output)-50:]
    }
}

// Plugin variable that NSD will load
var Plugin plugin.Plugin = &MyPlugin{}
```

### Build the Plugin

Create `Makefile`:

```makefile
.PHONY: build clean test

PLUGIN_NAME = my-plugin
PLUGIN_FILE = $(PLUGIN_NAME).so

build:
	go build -buildmode=plugin -o $(PLUGIN_FILE) .

clean:
	rm -f $(PLUGIN_FILE)

test:
	go test -v ./...

install: build
	sudo mkdir -p /usr/local/lib/nsd/plugins
	sudo cp $(PLUGIN_FILE) /usr/local/lib/nsd/plugins/

.DEFAULT_GOAL := build
```

Build the plugin:

```bash
make build
```

### Test the Plugin

```bash
# Test with NSD
sudo nsd -i eth0 --plugins ./my-plugin.so

# View plugin output (press 'G' in TUI)
```

## Advanced Plugin Features

### Packet Processing Plugin

```go
package main

import (
    "log"
    "strings"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/perplext/nsd/pkg/netcap"
    "github.com/perplext/nsd/pkg/plugin"
)

type PacketAnalyzerPlugin struct {
    monitor      *netcap.NetworkMonitor
    httpRequests int64
    dnsQueries   int64
    output       []string
    mutex        sync.RWMutex
}

func (p *PacketAnalyzerPlugin) Name() string {
    return "Advanced Packet Analyzer"
}

func (p *PacketAnalyzerPlugin) Init(nm *netcap.NetworkMonitor) error {
    p.monitor = nm
    p.output = make([]string, 0)
    
    // Register packet callback
    nm.RegisterPacketCallback(p.processPacket)
    
    return nil
}

func (p *PacketAnalyzerPlugin) processPacket(packet gopacket.Packet) {
    // Analyze HTTP traffic
    if httpLayer := packet.Layer(layers.LayerTypeHTTP); httpLayer != nil {
        http := httpLayer.(*layers.HTTP)
        p.analyzeHTTP(http)
    }
    
    // Analyze DNS traffic
    if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
        dns := dnsLayer.(*layers.DNS)
        p.analyzeDNS(dns)
    }
}

func (p *PacketAnalyzerPlugin) analyzeHTTP(http *layers.HTTP) {
    p.mutex.Lock()
    defer p.mutex.Unlock()
    
    p.httpRequests++
    
    if len(http.Payload) > 0 {
        payload := string(http.Payload)
        if strings.Contains(payload, "User-Agent:") {
            lines := strings.Split(payload, "\n")
            for _, line := range lines {
                if strings.HasPrefix(line, "User-Agent:") {
                    p.addOutput(fmt.Sprintf("HTTP User-Agent: %s", 
                        strings.TrimSpace(line[11:])))
                    break
                }
            }
        }
    }
}

func (p *PacketAnalyzerPlugin) analyzeDNS(dns *layers.DNS) {
    p.mutex.Lock()
    defer p.mutex.Unlock()
    
    p.dnsQueries++
    
    for _, question := range dns.Questions {
        p.addOutput(fmt.Sprintf("DNS Query: %s (%s)", 
            string(question.Name), question.Type.String()))
    }
}

func (p *PacketAnalyzerPlugin) addOutput(line string) {
    timestamp := time.Now().Format("15:04:05")
    p.output = append(p.output, fmt.Sprintf("[%s] %s", timestamp, line))
    
    if len(p.output) > 100 {
        p.output = p.output[len(p.output)-100:]
    }
}

func (p *PacketAnalyzerPlugin) GetDescription() string {
    return "Advanced packet analyzer for HTTP and DNS traffic"
}

func (p *PacketAnalyzerPlugin) GetOutput() []string {
    p.mutex.RLock()
    defer p.mutex.RUnlock()
    
    result := make([]string, 0, len(p.output)+2)
    result = append(result, 
        fmt.Sprintf("HTTP Requests: %d", p.httpRequests),
        fmt.Sprintf("DNS Queries: %d", p.dnsQueries),
    )
    result = append(result, p.output...)
    
    return result
}

var Plugin plugin.Plugin = &PacketAnalyzerPlugin{}
```

### Alert Integration Plugin

```go
package main

import (
    "encoding/json"
    "fmt"
    "net/http"
    "strings"
    "time"

    "github.com/perplext/nsd/pkg/alerts"
    "github.com/perplext/nsd/pkg/netcap"
    "github.com/perplext/nsd/pkg/plugin"
)

type AlertPlugin struct {
    monitor     *netcap.NetworkMonitor
    alertMgr    *alerts.AlertManager
    webhookURL  string
    thresholds  map[string]float64
}

func (p *AlertPlugin) Name() string {
    return "Custom Alert Plugin"
}

func (p *AlertPlugin) Init(nm *netcap.NetworkMonitor) error {
    p.monitor = nm
    p.alertMgr = alerts.NewAlertManager(1000)
    p.webhookURL = "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
    
    // Define alert thresholds
    p.thresholds = map[string]float64{
        "high_traffic": 100 * 1024 * 1024, // 100 MB/s
        "packet_rate":  10000,              // 10k packets/s
    }
    
    // Add webhook notification channel
    webhook := &alerts.WebhookChannel{
        URL: p.webhookURL,
        Headers: map[string]string{
            "Content-Type": "application/json",
        },
    }
    p.alertMgr.AddChannel(webhook)
    
    // Start monitoring
    go p.monitor()
    
    return nil
}

func (p *AlertPlugin) monitor() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    
    for range ticker.C {
        stats := p.monitor.GetStats()
        p.checkThresholds(stats)
    }
}

func (p *AlertPlugin) checkThresholds(stats map[string]interface{}) {
    if byteRate, ok := stats["ByteRate"].(float64); ok {
        if byteRate > p.thresholds["high_traffic"] {
            alert := &alerts.Alert{
                ID:          fmt.Sprintf("high-traffic-%d", time.Now().Unix()),
                Title:       "High Network Traffic",
                Description: fmt.Sprintf("Traffic rate %.2f MB/s exceeds threshold", 
                    byteRate/1024/1024),
                Level:       alerts.AlertWarning,
                Timestamp:   time.Now(),
                Source:      p.Name(),
                Data: map[string]interface{}{
                    "byte_rate": byteRate,
                    "threshold": p.thresholds["high_traffic"],
                },
            }
            p.alertMgr.TriggerAlert(alert)
        }
    }
}

func (p *AlertPlugin) GetDescription() string {
    return "Custom alerting plugin with Slack integration"
}

func (p *AlertPlugin) GetOutput() []string {
    alerts := p.alertMgr.GetAlerts(10)
    output := make([]string, 0, len(alerts)+1)
    
    output = append(output, fmt.Sprintf("Recent alerts (%d):", len(alerts)))
    
    for _, alert := range alerts {
        status := "ACTIVE"
        if alert.Resolved {
            status = "RESOLVED"
        }
        
        line := fmt.Sprintf("[%s] %s - %s (%s)",
            alert.Timestamp.Format("15:04:05"),
            alert.Level.String(),
            alert.Title,
            status,
        )
        output = append(output, line)
    }
    
    return output
}

var Plugin plugin.Plugin = &AlertPlugin{}
```

## Best Practices

### Performance Considerations

1. **Minimize Processing in Packet Callbacks:**
   ```go
   func (p *MyPlugin) processPacket(packet gopacket.Packet) {
       // Do minimal work here, queue heavy processing
       select {
       case p.packetQueue <- packet:
       default:
           // Drop packet if queue is full
       }
   }
   ```

2. **Use Buffered Channels:**
   ```go
   type MyPlugin struct {
       packetQueue chan gopacket.Packet
   }
   
   func (p *MyPlugin) Init(nm *netcap.NetworkMonitor) error {
       p.packetQueue = make(chan gopacket.Packet, 1000)
       go p.packetProcessor()
       return nil
   }
   ```

3. **Implement Graceful Shutdown:**
   ```go
   func (p *MyPlugin) Stop() error {
       close(p.stopChan)
       p.wg.Wait() // Wait for goroutines to finish
       return nil
   }
   ```

### Memory Management

1. **Limit Output History:**
   ```go
   func (p *MyPlugin) addOutput(line string) {
       p.output = append(p.output, line)
       if len(p.output) > 1000 {
           p.output = p.output[500:] // Keep last 500 lines
       }
   }
   ```

2. **Use Object Pools for Heavy Objects:**
   ```go
   var packetPool = sync.Pool{
       New: func() interface{} {
           return &PacketInfo{}
       },
   }
   
   func (p *MyPlugin) processPacket(packet gopacket.Packet) {
       info := packetPool.Get().(*PacketInfo)
       defer packetPool.Put(info)
       
       // Use info...
   }
   ```

### Error Handling

1. **Never Panic in Plugins:**
   ```go
   func (p *MyPlugin) processPacket(packet gopacket.Packet) {
       defer func() {
           if r := recover(); r != nil {
               log.Printf("Plugin %s panic: %v", p.Name(), r)
           }
       }()
       
       // Plugin logic...
   }
   ```

2. **Log Errors Appropriately:**
   ```go
   import "github.com/perplext/nsd/pkg/logging"
   
   func (p *MyPlugin) processData() {
       if err := p.doSomething(); err != nil {
           logging.Logger.Errorf("Plugin %s error: %v", p.Name(), err)
           return
       }
   }
   ```

### Configuration Management

1. **Support Configuration Files:**
   ```go
   type PluginConfig struct {
       Threshold    float64 `json:"threshold"`
       WebhookURL   string  `json:"webhook_url"`
       UpdateRate   int     `json:"update_rate_seconds"`
   }
   
   func (p *MyPlugin) loadConfig() error {
       configPath := filepath.Join(os.Getenv("HOME"), ".config", "nsd", 
           "plugins", p.Name()+".json")
       
       data, err := ioutil.ReadFile(configPath)
       if err != nil {
           return err
       }
       
       return json.Unmarshal(data, &p.config)
   }
   ```

## Testing and Debugging

### Unit Testing

Create `main_test.go`:

```go
package main

import (
    "testing"
    "time"

    "github.com/perplext/nsd/pkg/netcap"
)

func TestPluginInit(t *testing.T) {
    plugin := &MyPlugin{}
    
    // Mock network monitor
    monitor := &netcap.NetworkMonitor{}
    
    err := plugin.Init(monitor)
    if err != nil {
        t.Fatalf("Plugin initialization failed: %v", err)
    }
    
    if plugin.Name() == "" {
        t.Error("Plugin name should not be empty")
    }
}

func TestPluginOutput(t *testing.T) {
    plugin := &MyPlugin{}
    monitor := &netcap.NetworkMonitor{}
    
    plugin.Init(monitor)
    
    // Wait for some output
    time.Sleep(1 * time.Second)
    
    output := plugin.GetOutput()
    if len(output) == 0 {
        t.Error("Plugin should produce output")
    }
}

func BenchmarkPacketProcessing(b *testing.B) {
    plugin := &MyPlugin{}
    monitor := &netcap.NetworkMonitor{}
    plugin.Init(monitor)
    
    // Create mock packet
    packet := createMockPacket()
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        plugin.processPacket(packet)
    }
}
```

### Integration Testing

```bash
# Test plugin loading
go build -buildmode=plugin -o test-plugin.so .
nsd --test-plugin test-plugin.so

# Test with real traffic
sudo nsd -i lo --plugins ./test-plugin.so
```

### Debugging

1. **Enable Debug Logging:**
   ```bash
   export NSD_DEBUG=1
   export NSD_PLUGIN_DEBUG=1
   sudo nsd -i eth0 --plugins ./my-plugin.so
   ```

2. **Use Debug Builds:**
   ```bash
   go build -buildmode=plugin -gcflags="-N -l" -o debug-plugin.so .
   ```

3. **Add Debug Output:**
   ```go
   func (p *MyPlugin) debugf(format string, args ...interface{}) {
       if os.Getenv("NSD_PLUGIN_DEBUG") != "" {
           log.Printf("[DEBUG:%s] "+format, append([]interface{}{p.Name()}, args...)...)
       }
   }
   ```

## Plugin Examples

### Example Plugins Repository

Comprehensive examples are available at:
- `examples/plugins/simple/` - Basic plugin template
- `examples/plugins/http-analyzer/` - HTTP traffic analysis
- `examples/plugins/dns-monitor/` - DNS query monitoring
- `examples/plugins/alert-webhook/` - Webhook alerting
- `examples/plugins/geo-location/` - IP geolocation
- `examples/plugins/threat-intel/` - Threat intelligence integration

### Community Plugins

- **GeoIP Plugin:** Adds geographical location data to connections
- **Elasticsearch Plugin:** Exports data to Elasticsearch
- **Prometheus Plugin:** Exports metrics in Prometheus format
- **Discord Bot Plugin:** Sends alerts to Discord channels
- **Custom Protocol Analyzer:** Template for proprietary protocols

## Distribution and Deployment

### Plugin Packaging

1. **Create Release Package:**
   ```bash
   mkdir my-plugin-v1.0.0
   cp my-plugin.so my-plugin-v1.0.0/
   cp README.md my-plugin-v1.0.0/
   cp examples/ my-plugin-v1.0.0/ -r
   tar czf my-plugin-v1.0.0.tar.gz my-plugin-v1.0.0/
   ```

2. **Installation Script:**
   ```bash
   #!/bin/bash
   # install.sh
   set -e
   
   PLUGIN_NAME="my-plugin"
   INSTALL_DIR="/usr/local/lib/nsd/plugins"
   
   sudo mkdir -p "$INSTALL_DIR"
   sudo cp "${PLUGIN_NAME}.so" "$INSTALL_DIR/"
   sudo chmod 755 "$INSTALL_DIR/${PLUGIN_NAME}.so"
   
   echo "Plugin installed to $INSTALL_DIR"
   echo "Usage: nsd -i INTERFACE --plugins $INSTALL_DIR/${PLUGIN_NAME}.so"
   ```

### Plugin Registry

Consider submitting your plugin to the NSD Plugin Registry:

1. **Fork the registry repository**
2. **Add plugin metadata:**
   ```yaml
   name: my-awesome-plugin
   version: 1.0.0
   description: Does awesome things with network data
   author: Your Name <you@example.com>
   license: MIT
   repository: https://github.com/youruser/my-awesome-plugin
   download_url: https://github.com/youruser/my-awesome-plugin/releases/latest
   categories:
     - analysis
     - alerting
   supported_platforms:
     - linux
     - darwin
     - windows
   ```

3. **Submit pull request**

### Continuous Integration

Example GitHub Actions workflow:

```yaml
name: Build Plugin
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Go
      uses: actions/setup-go@v3
      with:
        go-version: 1.21
    
    - name: Install dependencies
      run: |
        sudo apt-get update
        sudo apt-get install -y libpcap-dev
    
    - name: Build plugin
      run: |
        go build -buildmode=plugin -o my-plugin.so .
    
    - name: Run tests
      run: go test -v ./...
    
    - name: Upload artifact
      uses: actions/upload-artifact@v3
      with:
        name: my-plugin
        path: my-plugin.so
```

This guide provides everything you need to develop powerful plugins for NSD. Start with the basic template and gradually add more advanced features as needed. Remember to follow best practices for performance and error handling to ensure your plugin works well with the core NSD application.