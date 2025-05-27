# Network Capture API Reference

## Package: `github.com/user/nsd/pkg/netcap`

The netcap package provides low-level network packet capture and analysis functionality using libpcap.

## Index

- [Constants](#constants)
- [Variables](#variables)
- [Types](#types)
  - [NetworkMonitor](#networkmonitor)
  - [Connection](#connection)
  - [ConnectionKey](#connectionkey)
  - [InterfaceStats](#interfacestats)
  - [PacketInfo](#packetinfo)
- [Functions](#functions)
- [Examples](#examples)

## Constants

```go
const (
    DefaultSnapLen       = 1600          // Default packet snapshot length
    DefaultTimeout       = time.Millisecond
    DefaultMaxBufferSize = 1000          // Maximum packet buffer size
)
```

## Variables

```go
var (
    ErrInterfaceNotFound = errors.New("network interface not found")
    ErrCaptureActive     = errors.New("capture already active on interface")
    ErrInvalidFilter     = errors.New("invalid BPF filter")
)
```

## Types

### NetworkMonitor

NetworkMonitor is the main type for capturing and analyzing network traffic.

```go
type NetworkMonitor struct {
    Interfaces     map[string]*InterfaceStats
    ActiveHandles  map[string]*pcap.Handle
    StopCapture    chan bool
    // contains filtered or unexported fields
}
```

#### func NewNetworkMonitor

```go
func NewNetworkMonitor() *NetworkMonitor
```

NewNetworkMonitor creates a new NetworkMonitor instance with default settings.

##### Example

```go
monitor := netcap.NewNetworkMonitor()
defer monitor.StopAllCaptures()
```

#### func (*NetworkMonitor) StartCapture

```go
func (nm *NetworkMonitor) StartCapture(interfaceName string) error
```

StartCapture begins packet capture on the specified network interface. The interface must exist and be accessible. Requires root/administrator privileges.

##### Parameters
- `interfaceName`: Name of the network interface (e.g., "eth0", "wlan0", "en0")

##### Returns
- `error`: Returns an error if:
  - Interface doesn't exist
  - Insufficient privileges
  - Capture already active on interface
  - Cannot open pcap handle

##### Example

```go
err := monitor.StartCapture("eth0")
if err != nil {
    if err == netcap.ErrInterfaceNotFound {
        log.Fatal("Interface not found")
    }
    log.Fatal("Failed to start capture:", err)
}
```

#### func (*NetworkMonitor) SetBPFFilter

```go
func (nm *NetworkMonitor) SetBPFFilter(filter string)
```

SetBPFFilter sets the Berkeley Packet Filter expression that will be applied to new packet captures. Does not affect currently active captures.

##### Parameters
- `filter`: BPF filter expression (e.g., "tcp port 80", "host 192.168.1.1")

##### Example

```go
// Capture only HTTP and HTTPS traffic
monitor.SetBPFFilter("tcp port 80 or tcp port 443")

// Capture traffic from specific subnet
monitor.SetBPFFilter("net 192.168.1.0/24")

// Complex filter
monitor.SetBPFFilter("(tcp port 22 or tcp port 23) and not host 10.0.0.1")
```

#### func (*NetworkMonitor) SetBpfFilter

```go
func (nm *NetworkMonitor) SetBpfFilter(interfaceName, filter string) error
```

SetBpfFilter applies a BPF filter to an active capture session.

##### Parameters
- `interfaceName`: Interface with active capture
- `filter`: BPF filter expression

##### Returns
- `error`: Returns an error if:
  - No active capture on interface
  - Invalid filter syntax

#### func (*NetworkMonitor) StopCapture

```go
func (nm *NetworkMonitor) StopCapture(interfaceName string) error
```

StopCapture stops packet capture on a specific interface.

##### Parameters
- `interfaceName`: Interface to stop capturing on

##### Returns
- `error`: Returns an error if no active capture on interface

#### func (*NetworkMonitor) StopAllCaptures

```go
func (nm *NetworkMonitor) StopAllCaptures()
```

StopAllCaptures stops all active packet captures and releases resources.

#### func (*NetworkMonitor) GetStats

```go
func (nm *NetworkMonitor) GetStats() map[string]interface{}
```

GetStats returns aggregated statistics for all monitored interfaces.

##### Returns
A map containing:
- `"TotalPackets"`: Total packets captured (uint64)
- `"TotalBytes"`: Total bytes captured (uint64)
- `"PacketsPerSecond"`: Current packet rate (float64)
- `"BytesPerSecond"`: Current byte rate (float64)
- `"ActiveConnections"`: Number of active connections (int)
- `"TopProtocols"`: Map of protocol names to packet counts

##### Example

```go
stats := monitor.GetStats()
fmt.Printf("Total packets: %d\n", stats["TotalPackets"].(uint64))
fmt.Printf("Active connections: %d\n", stats["ActiveConnections"].(int))

// Access top protocols
protocols := stats["TopProtocols"].(map[string]uint64)
for proto, count := range protocols {
    fmt.Printf("%s: %d packets\n", proto, count)
}
```

#### func (*NetworkMonitor) GetConnections

```go
func (nm *NetworkMonitor) GetConnections() map[ConnectionKey]*Connection
```

GetConnections returns a copy of all active network connections across all interfaces.

##### Returns
- Map of ConnectionKey to Connection pointers

##### Example

```go
connections := monitor.GetConnections()
for key, conn := range connections {
    fmt.Printf("%s:%d -> %s:%d [%s] %d bytes\n",
        conn.SrcIP, conn.SrcPort,
        conn.DstIP, conn.DstPort,
        conn.Protocol, conn.Size)
}
```

#### func (*NetworkMonitor) GetInterfaceStats

```go
func (nm *NetworkMonitor) GetInterfaceStats(interfaceName string) (*InterfaceStats, error)
```

GetInterfaceStats returns statistics for a specific interface.

##### Parameters
- `interfaceName`: Interface name

##### Returns
- `*InterfaceStats`: Interface statistics
- `error`: Error if interface not found

#### func (*NetworkMonitor) GetPacketBuffer

```go
func (nm *NetworkMonitor) GetPacketBuffer() []PacketInfo
```

GetPacketBuffer returns a copy of recent captured packets (up to maxBufferSize).

##### Returns
- `[]PacketInfo`: Slice of recent packets

#### func (*NetworkMonitor) IsLocalAddress

```go
func (nm *NetworkMonitor) IsLocalAddress(ip string) bool
```

IsLocalAddress checks if an IP address belongs to a local interface.

##### Parameters
- `ip`: IP address to check

##### Returns
- `bool`: True if address is local

### Connection

Connection represents an active network connection.

```go
type Connection struct {
    SrcIP    net.IP    // Source IP address
    DstIP    net.IP    // Destination IP address
    SrcPort  uint16    // Source port
    DstPort  uint16    // Destination port
    Protocol string    // Protocol name (e.g., "TCP", "UDP")
    Service  string    // Application protocol (e.g., "HTTP", "SSH")
    Size     uint64    // Total bytes transferred
    Packets  uint64    // Total packets
    LastSeen time.Time // Last activity timestamp
}
```

#### Connection Methods

##### func (*Connection) Duration

```go
func (c *Connection) Duration() time.Duration
```

Duration returns how long the connection has been active.

##### func (*Connection) IsActive

```go
func (c *Connection) IsActive(timeout time.Duration) bool
```

IsActive checks if the connection has had recent activity.

### ConnectionKey

ConnectionKey uniquely identifies a network connection.

```go
type ConnectionKey struct {
    SrcIP    string
    DstIP    string
    SrcPort  uint16
    DstPort  uint16
    Protocol string
}
```

#### func NewConnectionKey

```go
func NewConnectionKey(srcIP, dstIP string, srcPort, dstPort uint16, protocol string) ConnectionKey
```

NewConnectionKey creates a normalized connection key that treats connections as bidirectional.

### InterfaceStats

InterfaceStats contains statistics for a network interface.

```go
type InterfaceStats struct {
    Name        string                         // Interface name
    BytesIn     uint64                        // Bytes received
    BytesOut    uint64                        // Bytes sent
    PacketsIn   uint64                        // Packets received
    PacketsOut  uint64                        // Packets sent
    Connections map[ConnectionKey]*Connection // Active connections
    mutex       sync.RWMutex                  // Thread safety
}
```

#### InterfaceStats Methods

##### func (*InterfaceStats) AddPacket

```go
func (is *InterfaceStats) AddPacket(packet gopacket.Packet, isOutgoing bool)
```

AddPacket updates statistics based on a captured packet.

##### func (*InterfaceStats) GetConnectionCount

```go
func (is *InterfaceStats) GetConnectionCount() int
```

GetConnectionCount returns the number of active connections.

### PacketInfo

PacketInfo holds metadata for a captured packet.

```go
type PacketInfo struct {
    Timestamp   time.Time   // Capture timestamp
    Size        int         // Packet size
    Protocol    string      // Protocol name
    SrcIP       string      // Source IP
    DstIP       string      // Destination IP
    SrcPort     uint16      // Source port
    DstPort     uint16      // Destination port
    Interface   string      // Capture interface
    Direction   string      // "in" or "out"
}
```

## Functions

### func GetInterfaces

```go
func GetInterfaces() ([]pcap.Interface, error)
```

GetInterfaces returns a list of available network interfaces on the system.

#### Returns
- `[]pcap.Interface`: Available interfaces
- `error`: Error if interfaces cannot be enumerated

#### Example

```go
interfaces, err := netcap.GetInterfaces()
if err != nil {
    log.Fatal("Failed to get interfaces:", err)
}

for _, iface := range interfaces {
    fmt.Printf("Interface: %s\n", iface.Name)
    for _, addr := range iface.Addresses {
        fmt.Printf("  Address: %s\n", addr.IP)
    }
}
```

### func ValidateInterface

```go
func ValidateInterface(name string) error
```

ValidateInterface checks if a network interface exists and is valid.

#### Parameters
- `name`: Interface name to validate

#### Returns
- `error`: Error if interface is invalid or doesn't exist

## Examples

### Basic Packet Capture

```go
package main

import (
    "fmt"
    "log"
    "time"
    
    "github.com/user/nsd/pkg/netcap"
)

func main() {
    // Create monitor
    monitor := netcap.NewNetworkMonitor()
    
    // Set filter for HTTP traffic
    monitor.SetBPFFilter("tcp port 80")
    
    // Start capture
    err := monitor.StartCapture("eth0")
    if err != nil {
        log.Fatal(err)
    }
    defer monitor.StopAllCaptures()
    
    // Monitor for 30 seconds
    time.Sleep(30 * time.Second)
    
    // Print statistics
    stats := monitor.GetStats()
    fmt.Printf("Captured %d packets (%d bytes)\n",
        stats["TotalPackets"], stats["TotalBytes"])
    
    // Show connections
    connections := monitor.GetConnections()
    fmt.Printf("\nActive connections: %d\n", len(connections))
    for _, conn := range connections {
        fmt.Printf("  %s:%d -> %s:%d [%s] %s\n",
            conn.SrcIP, conn.SrcPort,
            conn.DstIP, conn.DstPort,
            conn.Protocol, conn.Service)
    }
}
```

### Multi-Interface Monitoring

```go
// Monitor multiple interfaces simultaneously
interfaces := []string{"eth0", "eth1", "wlan0"}

monitor := netcap.NewNetworkMonitor()
defer monitor.StopAllCaptures()

for _, iface := range interfaces {
    err := monitor.StartCapture(iface)
    if err != nil {
        log.Printf("Failed to start capture on %s: %v", iface, err)
        continue
    }
    log.Printf("Started capture on %s", iface)
}

// Monitor all interfaces
for {
    time.Sleep(5 * time.Second)
    
    for _, iface := range interfaces {
        stats, err := monitor.GetInterfaceStats(iface)
        if err != nil {
            continue
        }
        
        fmt.Printf("%s: In=%d bytes, Out=%d bytes, Connections=%d\n",
            iface, stats.BytesIn, stats.BytesOut,
            stats.GetConnectionCount())
    }
}
```

### Real-time Packet Analysis

```go
// Access packet buffer for real-time analysis
monitor := netcap.NewNetworkMonitor()
monitor.StartCapture("eth0")
defer monitor.StopAllCaptures()

ticker := time.NewTicker(1 * time.Second)
defer ticker.Stop()

for range ticker.C {
    packets := monitor.GetPacketBuffer()
    
    // Analyze recent packets
    protocolCount := make(map[string]int)
    for _, pkt := range packets {
        protocolCount[pkt.Protocol]++
    }
    
    fmt.Println("Recent packet distribution:")
    for proto, count := range protocolCount {
        fmt.Printf("  %s: %d packets\n", proto, count)
    }
}
```

## Best Practices

1. **Always defer StopAllCaptures()** to ensure resources are properly released
2. **Check for errors** when starting captures - common issues include missing privileges
3. **Use BPF filters** to reduce processing overhead in high-traffic environments
4. **Monitor resource usage** - packet capture can be CPU and memory intensive
5. **Handle interface changes** - interfaces may go up/down during monitoring

## Performance Tips

- Use specific BPF filters to reduce packet processing
- Limit packet snapshot length if full packets aren't needed
- Consider using multiple NetworkMonitor instances for different purposes
- Monitor the packet buffer size to prevent memory growth

## Thread Safety

All public methods of NetworkMonitor are thread-safe and can be called concurrently from multiple goroutines.