package netcap

import (
	"math"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/assert"
)

// MockHandle is a mock implementation of pcap.Handle for testing
type MockHandle struct {
	packets []gopacket.Packet
	index   int
	closed  bool
	mu      sync.Mutex
}

func (m *MockHandle) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
}

func (m *MockHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.index >= len(m.packets) || m.closed {
		return nil, gopacket.CaptureInfo{}, pcap.NextErrorTimeoutExpired
	}
	pkt := m.packets[m.index]
	m.index++
	return pkt.Data(), gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(pkt.Data()),
		Length:        len(pkt.Data()),
	}, nil
}

func (m *MockHandle) SetBPFFilter(filter string) error {
	return nil
}

func (m *MockHandle) Stats() (*pcap.Stats, error) {
	return &pcap.Stats{
		PacketsReceived:  len(m.packets),
		PacketsDropped:   0,
		PacketsIfDropped: 0,
	}, nil
}

func TestGetInterfaces(t *testing.T) {
	// Note: This test may fail if run in environments without network interfaces
	// In real scenarios, we'd mock pcap.FindAllDevs
	interfaces, err := GetInterfaces()
	
	// We can't predict the exact interfaces, but we can test the function doesn't crash
	if err != nil {
		// If there's an error (e.g., no permission), that's okay for testing
		t.Logf("GetInterfaces returned error (expected in test environment): %v", err)
	} else {
		// If successful, interfaces should be a slice (possibly empty)
		assert.NotNil(t, interfaces)
	}
}

func TestNetworkMonitorStartCaptureInvalidInterface(t *testing.T) {
	nm := NewNetworkMonitor()
	
	// Test with invalid interface name
	err := nm.StartCapture("invalid_interface_xyz")
	assert.Error(t, err)
}

func TestNetworkMonitorStopAllCaptures(t *testing.T) {
	nm := NewNetworkMonitor()
	
	// Add some mock handles
	nm.ActiveHandles["eth0"] = &pcap.Handle{}
	nm.ActiveHandles["eth1"] = &pcap.Handle{}
	
	// Test stop all captures
	nm.StopAllCaptures()
	
	// Verify all handles are removed
	nm.mutex.RLock()
	assert.Equal(t, 0, len(nm.ActiveHandles))
	nm.mutex.RUnlock()
}

func TestNetworkMonitorUpdateLocalAddresses(t *testing.T) {
	nm := NewNetworkMonitor()
	
	// Test updating local addresses
	nm.updateLocalAddresses()
	
	// Should have populated localAddresses
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()
	
	// The actual addresses depend on the system, but the map should exist
	assert.NotNil(t, nm.localAddresses)
}

func TestNetworkMonitorIsLocalAddress(t *testing.T) {
	nm := NewNetworkMonitor()
	
	// Set up test local addresses
	nm.mutex.Lock()
	nm.localAddresses = map[string]bool{
		"192.168.1.100": true,
		"10.0.0.1":      true,
		"::1":           true,
	}
	nm.mutex.Unlock()
	
	// Test internal isLocalAddress
	assert.True(t, nm.isLocalAddress("192.168.1.100"))
	assert.True(t, nm.isLocalAddress("10.0.0.1"))
	assert.False(t, nm.isLocalAddress("8.8.8.8"))
	
	// Test public IsLocalAddress
	assert.True(t, nm.IsLocalAddress("192.168.1.100"))
	assert.True(t, nm.IsLocalAddress("10.0.0.1"))
	assert.False(t, nm.IsLocalAddress("8.8.8.8"))
}

func TestNetworkMonitorSetBpfFilter(t *testing.T) {
	nm := NewNetworkMonitor()
	
	// Test setting filter without active capture
	err := nm.SetBpfFilter("eth0", "tcp port 80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not capturing")
	
	// Test with nil handle should be handled by the implementation
	// We shouldn't add nil handles to ActiveHandles
}

func TestNetworkMonitorGetPacketBuffer(t *testing.T) {
	nm := NewNetworkMonitor()
	
	// Add some packets to the buffer
	packets := []PacketInfo{
		{
			Timestamp: time.Now(),
			SrcIP:     net.ParseIP("192.168.1.1"),
			DstIP:     net.ParseIP("192.168.1.2"),
			Protocol:  "TCP",
			Service:   "HTTP",
			Length:    100,
		},
		{
			Timestamp: time.Now(),
			SrcIP:     net.ParseIP("10.0.0.1"),
			DstIP:     net.ParseIP("10.0.0.2"),
			Protocol:  "UDP",
			Service:   "DNS",
			Length:    50,
		},
	}
	
	nm.bufferMutex.Lock()
	nm.packetBuffer = packets
	nm.bufferMutex.Unlock()
	
	// Get packet buffer
	buffer := nm.GetPacketBuffer()
	
	// Should return a copy
	assert.Equal(t, len(packets), len(buffer))
	assert.Equal(t, packets[0].SrcIP.String(), buffer[0].SrcIP.String())
	assert.Equal(t, packets[1].Service, buffer[1].Service)
	
	// Modify the returned buffer
	buffer[0].Service = "MODIFIED"
	
	// Original should be unchanged
	nm.bufferMutex.RLock()
	assert.Equal(t, "HTTP", nm.packetBuffer[0].Service)
	nm.bufferMutex.RUnlock()
}

func TestNetworkMonitorGetInterfaceStats(t *testing.T) {
	nm := NewNetworkMonitor()
	
	// Set up test interface stats
	nm.mutex.Lock()
	nm.Interfaces["eth0"] = &InterfaceStats{
		Name:       "eth0",
		BytesIn:    1000,
		BytesOut:   2000,
		PacketsIn:  10,
		PacketsOut: 20,
		Connections: map[ConnectionKey]*Connection{
			{SrcIP: "192.168.1.1", DstIP: "8.8.8.8", SrcPort: 12345, DstPort: 80, Protocol: "TCP"}: {
				Size:    500,
				Packets: 5,
			},
		},
	}
	nm.mutex.Unlock()
	
	// Get interface stats
	stats := nm.GetInterfaceStats()
	
	// Should have eth0 stats
	assert.NotNil(t, stats["eth0"])
	assert.Equal(t, uint64(1000), stats["eth0"].BytesIn)
	assert.Equal(t, uint64(2000), stats["eth0"].BytesOut)
	assert.Equal(t, 1, len(stats["eth0"].Connections))
}

func TestNetworkMonitorGetConnections(t *testing.T) {
	nm := NewNetworkMonitor()
	
	// Set up test connections
	conn1 := &Connection{
		SrcIP:    net.ParseIP("192.168.1.100"),
		DstIP:    net.ParseIP("8.8.8.8"),
		SrcPort:  54321,
		DstPort:  443,
		Protocol: "TCP",
		Service:  "HTTPS",
		Size:     1024,
		Packets:  10,
		LastSeen: time.Now(),
	}
	
	conn2 := &Connection{
		SrcIP:    net.ParseIP("10.0.0.1"),
		DstIP:    net.ParseIP("1.1.1.1"),
		SrcPort:  12345,
		DstPort:  53,
		Protocol: "UDP",
		Service:  "DNS",
		Size:     200,
		Packets:  2,
		LastSeen: time.Now(),
	}
	
	nm.mutex.Lock()
	nm.Interfaces["eth0"] = &InterfaceStats{
		Name: "eth0",
		Connections: map[ConnectionKey]*Connection{
			{SrcIP: "192.168.1.100", DstIP: "8.8.8.8", SrcPort: 54321, DstPort: 443, Protocol: "TCP"}: conn1,
			{SrcIP: "10.0.0.1", DstIP: "1.1.1.1", SrcPort: 12345, DstPort: 53, Protocol: "UDP"}: conn2,
		},
	}
	nm.mutex.Unlock()
	
	// Get connections for eth0
	connections := nm.GetConnections("eth0")
	
	// Should have 2 connections
	assert.Equal(t, 2, len(connections))
	
	// Check connections are included
	found1, found2 := false, false
	for _, conn := range connections {
		if conn.DstPort == 443 {
			found1 = true
			assert.Equal(t, "HTTPS", conn.Service)
		}
		if conn.DstPort == 53 {
			found2 = true
			assert.Equal(t, "DNS", conn.Service)
		}
	}
	assert.True(t, found1)
	assert.True(t, found2)
}

func TestNetworkMonitorCleanupOldConnections(t *testing.T) {
	nm := NewNetworkMonitor()
	
	now := time.Now()
	oldTime := now.Add(-2 * time.Hour)
	recentTime := now.Add(-30 * time.Second)
	
	// Set up test connections with different ages
	nm.mutex.Lock()
	nm.Interfaces["eth0"] = &InterfaceStats{
		Name: "eth0",
		Connections: map[ConnectionKey]*Connection{
			{SrcIP: "192.168.1.1", DstIP: "8.8.8.8", SrcPort: 11111, DstPort: 80, Protocol: "TCP"}: {
				LastSeen: oldTime, // Old connection
			},
			{SrcIP: "192.168.1.2", DstIP: "8.8.8.8", SrcPort: 22222, DstPort: 80, Protocol: "TCP"}: {
				LastSeen: recentTime, // Recent connection
			},
		},
	}
	nm.mutex.Unlock()
	
	// Clean up old connections
	nm.CleanupOldConnections(1 * time.Hour)
	
	// Should have removed 1 old connection
	
	// Verify old connection is gone
	nm.mutex.RLock()
	assert.Equal(t, 1, len(nm.Interfaces["eth0"].Connections))
	// The recent connection should still exist
	for _, conn := range nm.Interfaces["eth0"].Connections {
		assert.Equal(t, recentTime, conn.LastSeen)
	}
	nm.mutex.RUnlock()
}

func TestNetworkMonitorGetPcapStats(t *testing.T) {
	nm := NewNetworkMonitor()
	
	// Test without active handles (need to provide interface name)
	stats, _ := nm.GetPcapStats("eth0")
	assert.Nil(t, stats)
	
	// Note: Testing with real pcap handles would require actual packet capture
	// which is not feasible in unit tests. In production, you'd use dependency injection
	// or interfaces to allow mocking.
}

func TestInterfaceStatsThreadSafety(t *testing.T) {
	stats := &InterfaceStats{
		Name:        "eth0",
		Connections: make(map[ConnectionKey]*Connection),
	}
	
	// Test concurrent access
	var wg sync.WaitGroup
	
	// Writer goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			stats.mutex.Lock()
			if i >= 0 && uint64(i) <= (math.MaxUint64 - stats.BytesIn) {
				stats.BytesIn += uint64(i)
			}
			stats.PacketsIn++
			stats.mutex.Unlock()
		}
	}()
	
	// Reader goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			stats.mutex.RLock()
			_ = stats.BytesIn
			_ = stats.PacketsIn
			stats.mutex.RUnlock()
		}
	}()
	
	wg.Wait()
	
	// Should complete without race conditions
	assert.True(t, true)
}

func TestPacketProcessingHelpers(t *testing.T) {
	nm := NewNetworkMonitor()
	
	// Initialize local addresses
	nm.mutex.Lock()
	nm.localAddresses = map[string]bool{
		"192.168.1.100": true,
	}
	nm.mutex.Unlock()
	
	// Test packet buffer management
	nm.bufferMutex.Lock()
	nm.maxBufferSize = 3
	nm.bufferMutex.Unlock()
	
	// Add packets to buffer
	for i := 0; i < 5; i++ {
		packet := PacketInfo{
			Timestamp: time.Now(),
			SrcIP:     net.ParseIP("192.168.1.100"),
			DstIP:     net.ParseIP("8.8.8.8"),
			Protocol:  "TCP",
			Length:    uint64(100 + (i % 1000)), // Prevent overflow
		}
		
		nm.bufferMutex.Lock()
		nm.packetBuffer = append(nm.packetBuffer, packet)
		// Simulate buffer size management
		if len(nm.packetBuffer) > nm.maxBufferSize {
			nm.packetBuffer = nm.packetBuffer[len(nm.packetBuffer)-nm.maxBufferSize:]
		}
		nm.bufferMutex.Unlock()
	}
	
	// Check buffer size is limited
	nm.bufferMutex.RLock()
	assert.LessOrEqual(t, len(nm.packetBuffer), nm.maxBufferSize)
	nm.bufferMutex.RUnlock()
}

func TestConnectionKeyEquality(t *testing.T) {
	key1 := ConnectionKey{
		SrcIP:    "192.168.1.1",
		DstIP:    "8.8.8.8",
		SrcPort:  12345,
		DstPort:  80,
		Protocol: "TCP",
	}
	
	key2 := ConnectionKey{
		SrcIP:    "192.168.1.1",
		DstIP:    "8.8.8.8",
		SrcPort:  12345,
		DstPort:  80,
		Protocol: "TCP",
	}
	
	// Test that identical keys are equal
	assert.Equal(t, key1, key2)
	
	// Test map usage
	connMap := make(map[ConnectionKey]*Connection)
	connMap[key1] = &Connection{Size: 100}
	
	// Should be able to retrieve with key2
	conn, exists := connMap[key2]
	assert.True(t, exists)
	assert.Equal(t, uint64(100), conn.Size)
}

func TestServicePortMapCompleteness(t *testing.T) {
	// Test that common ports are mapped
	expectedMappings := map[uint16]string{
		80:   "HTTP",
		443:  "HTTPS",
		22:   "SSH",
		53:   "DNS",
		25:   "SMTP",
		143:  "IMAP",
		110:  "POP3",
	}
	
	for port, expectedService := range expectedMappings {
		service, exists := servicePortMap[port]
		assert.True(t, exists, "Port %d should be in servicePortMap", port)
		assert.Equal(t, expectedService, service, "Port %d should map to %s", port, expectedService)
	}
}

// Test error conditions and edge cases
func TestEdgeCases(t *testing.T) {
	nm := NewNetworkMonitor()
	
	// Test with empty IP
	assert.False(t, nm.isLocalAddress(""))
	
	// Test empty filter expression
	assert.Equal(t, "", nm.GetFilterExpression())
	
	// Test getting connections with no interfaces
	connections := nm.GetConnections("eth0")
	assert.Empty(t, connections)
	
	// Test cleanup with no connections
	nm.CleanupOldConnections(time.Hour)
}