package netcap

import (
	"fmt"
	"log"
	"math"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Connection represents a network connection
type Connection struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Protocol string
	Service  string         // application/service protocol
	Size     uint64
	Packets  uint64
	LastSeen time.Time
}

// ConnectionKey is used as a map key for connections
type ConnectionKey struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol string
}

// InterfaceStats contains statistics for a network interface
type InterfaceStats struct {
	Name        string
	BytesIn     uint64
	BytesOut    uint64
	PacketsIn   uint64
	PacketsOut  uint64
	Connections map[ConnectionKey]*Connection
	mutex       sync.RWMutex
}

// PacketInfo holds metadata for a captured packet
type PacketInfo struct {
	Timestamp time.Time
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Protocol  string
	Service   string         // application/service protocol (HTTP, DNS, etc.)
	Length    uint64
	Data      []byte         // raw packet data
}

// servicePortMap maps well-known ports to service names
var servicePortMap = map[uint16]string{
	80:   "HTTP",
	443:  "HTTPS",
	22:   "SSH",
	53:   "DNS",
	123:  "NTP",
	67:   "DHCP",
	68:   "DHCP",
	25:   "SMTP",
	143:  "IMAP",
	110:  "POP3",
}

// detectService returns the service name for given transport protocol and ports, falling back to the protocol
func detectService(proto string, srcPort, dstPort uint16) string {
	if proto != "TCP" && proto != "UDP" {
		return proto
	}
	if name, ok := servicePortMap[dstPort]; ok {
		return name
	}
	if name, ok := servicePortMap[srcPort]; ok {
		return name
	}
	return proto
}

// NetworkMonitor monitors network traffic
type NetworkMonitor struct {
	Interfaces     map[string]*InterfaceStats
	ActiveHandles  map[string]*pcap.Handle
	StopCapture    chan bool
	mutex          sync.RWMutex
	localAddresses map[string]bool
	filterExpression string           // current BPF filter
	packetBuffer     []PacketInfo     // recent packets buffer
	bufferMutex      sync.RWMutex
	maxBufferSize    int
}

// NewNetworkMonitor creates a new network monitor
func NewNetworkMonitor() *NetworkMonitor {
	return &NetworkMonitor{
		Interfaces:     make(map[string]*InterfaceStats),
		ActiveHandles:  make(map[string]*pcap.Handle),
		StopCapture:    make(chan bool),
		localAddresses: make(map[string]bool),
		filterExpression: "",
		packetBuffer:     make([]PacketInfo, 0),
		bufferMutex:      sync.RWMutex{},
		maxBufferSize:    1000,
	}
}

// GetInterfaces returns a list of available network interfaces
func GetInterfaces() ([]pcap.Interface, error) {
	return pcap.FindAllDevs()
}

// StartCapture starts capturing packets on the specified interface
func (nm *NetworkMonitor) StartCapture(interfaceName string) error {
	// Check if we're already capturing on this interface
	nm.mutex.Lock()
	if _, exists := nm.ActiveHandles[interfaceName]; exists {
		nm.mutex.Unlock()
		return fmt.Errorf("already capturing on interface %s", interfaceName)
	}
	nm.mutex.Unlock()

	// Initialize interface stats if not already done
	nm.mutex.Lock()
	if _, exists := nm.Interfaces[interfaceName]; !exists {
		nm.Interfaces[interfaceName] = &InterfaceStats{
			Name:        interfaceName,
			Connections: make(map[ConnectionKey]*Connection),
		}
	}
	nm.mutex.Unlock()

	// Get local addresses
	nm.updateLocalAddresses()

	// Open the device for capturing
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("error opening interface %s: %v", interfaceName, err)
	}

	// Apply BPF filter if set
	nm.mutex.Lock()
	if nm.filterExpression != "" {
		if err := handle.SetBPFFilter(nm.filterExpression); err != nil {
			nm.mutex.Unlock()
			handle.Close()
			return fmt.Errorf("error setting BPF filter: %v", err)
		}
	}
	nm.ActiveHandles[interfaceName] = handle
	nm.mutex.Unlock()

	// Start packet processing in a goroutine
	go nm.processPackets(interfaceName, handle)

	return nil
}

// StopAllCaptures stops all active packet captures
func (nm *NetworkMonitor) StopAllCaptures() {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()

	// Signal to stop
	close(nm.StopCapture)

	// Close all handles
	for name, handle := range nm.ActiveHandles {
		handle.Close()
		delete(nm.ActiveHandles, name)
	}
}

// processPackets processes packets from the given handle
func (nm *NetworkMonitor) processPackets(interfaceName string, handle *pcap.Handle) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	
	for {
		select {
		case <-nm.StopCapture:
			return
		case packet, ok := <-packetSource.Packets():
			if !ok {
				return
			}
			nm.processPacket(interfaceName, packet)
		}
	}
}

// processPacket processes a single packet
func (nm *NetworkMonitor) processPacket(interfaceName string, packet gopacket.Packet) {
	// Get interface stats
	nm.mutex.RLock()
	ifStats, exists := nm.Interfaces[interfaceName]
	nm.mutex.RUnlock()
	
	if !exists {
		return
	}

	// Extract network layer info (IP)
	ipLayer := packet.NetworkLayer()
	if ipLayer == nil {
		return
	}
	
	ipPacket, ok := ipLayer.(*layers.IPv4)
	if !ok {
		return
	}

	// Get packet size
	packetSize := uint64(len(packet.Data()))

	// Determine direction (in/out) based on source/dest IPs
	srcIP := ipPacket.SrcIP
	dstIP := ipPacket.DstIP
	
	isOutbound := nm.isLocalAddress(srcIP.String())
	isInbound := nm.isLocalAddress(dstIP.String())

	// Update interface stats
	ifStats.mutex.Lock()
	if isOutbound {
		ifStats.BytesOut += packetSize
		ifStats.PacketsOut++
	}
	if isInbound {
		ifStats.BytesIn += packetSize
		ifStats.PacketsIn++
	}
	ifStats.mutex.Unlock()

	// Extract transport layer info (TCP/UDP)
	var srcPort, dstPort uint16
	var protocol string

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		protocol = "TCP"
	} else {
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			srcPort = uint16(udp.SrcPort)
			dstPort = uint16(udp.DstPort)
			protocol = "UDP"
		} else {
			// Neither TCP nor UDP
			protocol = ipPacket.Protocol.String()
		}
	}

	// Create connection key
	connKey := ConnectionKey{
		SrcIP:    srcIP.String(),
		DstIP:    dstIP.String(),
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: protocol,
	}

	// Update connection stats
	ifStats.mutex.Lock()
	conn, exists := ifStats.Connections[connKey]
	if !exists {
		conn = &Connection{
			SrcIP:    srcIP,
			DstIP:    dstIP,
			SrcPort:  srcPort,
			DstPort:  dstPort,
			Protocol: protocol,
			Service:  detectService(protocol, srcPort, dstPort),
		}
		ifStats.Connections[connKey] = conn
	}
	
	conn.Size += packetSize
	conn.Packets++
	conn.LastSeen = time.Now()
	ifStats.mutex.Unlock()

	// Add to packet buffer
	nm.bufferMutex.Lock()
	pi := PacketInfo{
		Timestamp: packet.Metadata().Timestamp,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  protocol,
		Service:   detectService(protocol, srcPort, dstPort),
		Length:    packetSize,
		Data:      append([]byte(nil), packet.Data()...),
	}
	nm.packetBuffer = append(nm.packetBuffer, pi)
	if len(nm.packetBuffer) > nm.maxBufferSize {
		nm.packetBuffer = nm.packetBuffer[len(nm.packetBuffer)-nm.maxBufferSize:]
	}
	nm.bufferMutex.Unlock()
}

// updateLocalAddresses gets all local IP addresses
func (nm *NetworkMonitor) updateLocalAddresses() {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf("Error getting local addresses: %v", err)
		return
	}

	nm.mutex.Lock()
	defer nm.mutex.Unlock()
	
	// Clear existing addresses
	nm.localAddresses = make(map[string]bool)
	
	// Add all local addresses
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			nm.localAddresses[ipnet.IP.String()] = true
		}
	}
}

// isLocalAddress checks if an IP address is local
func (nm *NetworkMonitor) isLocalAddress(ip string) bool {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()
	
	return nm.localAddresses[ip]
}

// IsLocalAddress returns whether the given IP is local to any interface
func (nm *NetworkMonitor) IsLocalAddress(ip string) bool {
	return nm.isLocalAddress(ip)
}

// SetBpfFilter applies a BPF filter on an active capture handle
func (nm *NetworkMonitor) SetBpfFilter(interfaceName, filter string) error {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()
	handle, ok := nm.ActiveHandles[interfaceName]
	if !ok {
		return fmt.Errorf("interface %s not capturing", interfaceName)
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("error setting BPF filter on %s: %v", interfaceName, err)
	}
	nm.filterExpression = filter
	return nil
}

// SetBPFFilter sets the BPF filter expression to be used for new captures
func (nm *NetworkMonitor) SetBPFFilter(filter string) {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()
	nm.filterExpression = filter
}

// GetPacketBuffer returns a copy of recent captured packets
func (nm *NetworkMonitor) GetPacketBuffer() []PacketInfo {
	nm.bufferMutex.RLock()
	defer nm.bufferMutex.RUnlock()
	buf := make([]PacketInfo, len(nm.packetBuffer))
	copy(buf, nm.packetBuffer)
	return buf
}

// GetFilterExpression returns the current BPF filter string
func (nm *NetworkMonitor) GetFilterExpression() string {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()
	return nm.filterExpression
}

// GetInterfaceStats returns statistics for all interfaces
func (nm *NetworkMonitor) GetInterfaceStats() map[string]*InterfaceStats {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()
	
	// Create a copy to avoid concurrent access issues
	statsCopy := make(map[string]*InterfaceStats)
	for name, stats := range nm.Interfaces {
		statsCopy[name] = stats
	}
	
	return statsCopy
}

// GetConnections returns all connections for a specific interface
func (nm *NetworkMonitor) GetConnections(interfaceName string) []*Connection {
	nm.mutex.RLock()
	ifStats, exists := nm.Interfaces[interfaceName]
	nm.mutex.RUnlock()
	
	if !exists {
		return nil
	}
	
	ifStats.mutex.RLock()
	defer ifStats.mutex.RUnlock()
	
	// Create a slice of connections
	connections := make([]*Connection, 0, len(ifStats.Connections))
	for _, conn := range ifStats.Connections {
		connections = append(connections, conn)
	}
	
	return connections
}

// CleanupOldConnections removes connections that haven't been seen recently
func (nm *NetworkMonitor) CleanupOldConnections(maxAge time.Duration) {
	now := time.Now()
	
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()
	
	for _, ifStats := range nm.Interfaces {
		ifStats.mutex.Lock()
		
		for key, conn := range ifStats.Connections {
			if now.Sub(conn.LastSeen) > maxAge {
				delete(ifStats.Connections, key)
			}
		}
		
		ifStats.mutex.Unlock()
	}
}

// GetPcapStats returns pcap statistics for a given interface (received, dropped, interface-dropped)
func (nm *NetworkMonitor) GetPcapStats(interfaceName string) (*pcap.Stats, error) {
	nm.mutex.RLock()
	handle, ok := nm.ActiveHandles[interfaceName]
	nm.mutex.RUnlock()
	if !ok {
		return nil, fmt.Errorf("interface %s not capturing", interfaceName)
	}
	stats, err := handle.Stats()
	if err != nil {
		return nil, err
	}
	return stats, nil
}

// GetStats returns aggregated statistics for all interfaces
func (nm *NetworkMonitor) GetStats() map[string]interface{} {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()
	
	totalPackets := int64(0)
	totalBytes := int64(0)
	packetRate := float64(0)
	byteRate := float64(0)
	
	for _, iface := range nm.Interfaces {
		// Check for overflow before conversion
		packetSum := iface.PacketsIn + iface.PacketsOut
		if packetSum < iface.PacketsIn { // Overflow check
			totalPackets = math.MaxInt64
		} else if packetSum > uint64(math.MaxInt64-totalPackets) {
			totalPackets = math.MaxInt64
		} else {
			totalPackets += int64(packetSum)
		}
		
		byteSum := iface.BytesIn + iface.BytesOut
		if byteSum < iface.BytesIn { // Overflow check
			totalBytes = math.MaxInt64
		} else if byteSum > uint64(math.MaxInt64-totalBytes) {
			totalBytes = math.MaxInt64
		} else {
			totalBytes += int64(byteSum)
		}
	}
	
	return map[string]interface{}{
		"TotalPackets": totalPackets,
		"TotalBytes":   totalBytes,
		"PacketRate":   packetRate,
		"ByteRate":     byteRate,
	}
}
