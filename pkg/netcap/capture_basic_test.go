package netcap

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBasicStructures(t *testing.T) {
	// Test Connection
	conn := &Connection{
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
	
	assert.NotNil(t, conn.SrcIP)
	assert.Equal(t, "8.8.8.8", conn.DstIP.String())
	assert.Equal(t, "HTTPS", conn.Service)

	// Test ConnectionKey
	key := ConnectionKey{
		SrcIP:    "192.168.1.100",
		DstIP:    "8.8.8.8",
		SrcPort:  54321,
		DstPort:  443,
		Protocol: "TCP",
	}
	
	assert.Equal(t, "192.168.1.100", key.SrcIP)
	assert.Equal(t, uint16(443), key.DstPort)
}

func TestServiceDetection(t *testing.T) {
	tests := []struct {
		proto    string
		srcPort  uint16
		dstPort  uint16
		expected string
	}{
		{"TCP", 54321, 80, "HTTP"},
		{"TCP", 54321, 443, "HTTPS"},
		{"TCP", 54321, 22, "SSH"},
		{"UDP", 54321, 53, "DNS"},
		{"TCP", 54321, 12345, "TCP"},
		{"ICMP", 0, 0, "ICMP"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			service := detectService(tt.proto, tt.srcPort, tt.dstPort)
			assert.Equal(t, tt.expected, service)
		})
	}
}

func TestNetworkMonitorCreation(t *testing.T) {
	nm := NewNetworkMonitor()
	
	assert.NotNil(t, nm)
	assert.NotNil(t, nm.Interfaces)
	assert.NotNil(t, nm.ActiveHandles)
	assert.NotNil(t, nm.StopCapture)
}