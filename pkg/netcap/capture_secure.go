package netcap

import (
	"fmt"
	"net"
	"time"
	
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/perplext/nsd/pkg/security"
)

// SecureNetworkMonitor provides network monitoring with security validation
type SecureNetworkMonitor struct {
	*NetworkMonitor
	validator  *security.Validator
	bpfFilter  string
}

// NewSecureNetworkMonitor creates a new secure network monitor
func NewSecureNetworkMonitor() *SecureNetworkMonitor {
	return &SecureNetworkMonitor{
		NetworkMonitor: NewNetworkMonitor(),
		validator:      security.NewValidator(),
	}
}

// SetBPFFilter sets and validates a BPF filter
func (nm *SecureNetworkMonitor) SetBPFFilter(filter string) error {
	if err := nm.validator.ValidateBPFFilter(filter); err != nil {
		return fmt.Errorf("invalid BPF filter: %w", err)
	}
	nm.bpfFilter = filter
	return nil
}

// StartSecureCapture starts packet capture with security validation
func (nm *SecureNetworkMonitor) StartSecureCapture(interfaceName string) error {
	// Validate interface name
	if err := nm.validator.ValidateInterfaceName(interfaceName); err != nil {
		return fmt.Errorf("invalid interface name: %w", err)
	}
	
	// Verify interface exists
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to list interfaces: %w", err)
	}
	
	found := false
	for _, iface := range ifaces {
		if iface.Name == interfaceName {
			found = true
			break
		}
	}
	
	if !found {
		return fmt.Errorf("interface %s not found", interfaceName)
	}
	
	// Set up packet capture with security defaults
	handle, err := pcap.OpenLive(
		interfaceName,
		1600,              // Snapshot length
		true,              // Promiscuous mode
		time.Millisecond,  // Timeout
	)
	if err != nil {
		return fmt.Errorf("failed to open interface: %w", err)
	}
	
	// Apply BPF filter if set
	if nm.bpfFilter != "" {
		if err := handle.SetBPFFilter(nm.bpfFilter); err != nil {
			handle.Close()
			return fmt.Errorf("failed to set BPF filter: %w", err)
		}
	}
	
	nm.handle = handle
	nm.packetSource = gopacket.NewPacketSource(handle, handle.LinkType())
	
	// Start packet processing goroutine
	go nm.processPackets()
	
	return nil
}

// ValidatePacket performs security validation on captured packets
func (nm *SecureNetworkMonitor) ValidatePacket(packet gopacket.Packet) error {
	// Check packet size
	if len(packet.Data()) > 65535 {
		return fmt.Errorf("packet size exceeds maximum")
	}
	
	// Additional packet validation can be added here
	// - Check for malformed packets
	// - Validate protocol headers
	// - Detect suspicious patterns
	
	return nil
}

// GetSecureStats returns sanitized statistics
func (nm *SecureNetworkMonitor) GetSecureStats() map[string]interface{} {
	stats := nm.GetStats()
	
	// Sanitize statistics to prevent information leakage
	secureStats := make(map[string]interface{})
	
	// Only include safe statistics
	safeKeys := []string{
		"TotalPackets",
		"TotalBytes", 
		"PacketsPerSecond",
		"BytesPerSecond",
		"ActiveConnections",
		"TopProtocols",
	}
	
	for _, key := range safeKeys {
		if val, ok := stats[key]; ok {
			secureStats[key] = val
		}
	}
	
	return secureStats
}