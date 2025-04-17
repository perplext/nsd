package netcap

import (
	"testing"
)

func TestNewNetworkMonitorDefaults(t *testing.T) {
	nm := NewNetworkMonitor()
	if nm == nil {
		t.Fatal("NewNetworkMonitor returned nil")
	}
	if nm.filterExpression != "" {
		t.Errorf("expected default filterExpression %q, got %q", "", nm.filterExpression)
	}
	if len(nm.packetBuffer) != 0 {
		t.Errorf("expected empty packetBuffer, got len %d", len(nm.packetBuffer))
	}
	if nm.maxBufferSize != 1000 {
		t.Errorf("expected maxBufferSize 1000, got %d", nm.maxBufferSize)
	}
}

func TestGetFilterExpression(t *testing.T) {
	nm := NewNetworkMonitor()
	nm.filterExpression = "tcp"
	if got := nm.GetFilterExpression(); got != "tcp" {
		t.Errorf("GetFilterExpression = %q, want %q", got, "tcp")
	}
}

func TestGetPacketBufferCopy(t *testing.T) {
	nm := NewNetworkMonitor()
	nm.packetBuffer = []PacketInfo{{Protocol: "X"}}
	buf := nm.GetPacketBuffer()
	if len(buf) != 1 {
		t.Fatalf("buf length = %d, want 1", len(buf))
	}
	buf[0].Protocol = "Y"
	if nm.packetBuffer[0].Protocol != "X" {
		t.Errorf("original packetBuffer mutated to %q", nm.packetBuffer[0].Protocol)
	}
}

func TestSetBpfFilterNotCapturing(t *testing.T) {
	nm := NewNetworkMonitor()
	if err := nm.SetBpfFilter("eth0", "tcp"); err == nil {
		t.Errorf("expected error when setting filter on non-capturing interface, got nil")
	}
}

// TestDetectService verifies mapping of ports and protocols to service names
func TestDetectService(t *testing.T) {
	cases := []struct{proto string; src, dst uint16; want string}{
		{"TCP", 0, 80, "HTTP"},
		{"TCP", 0, 443, "HTTPS"},
		{"UDP", 0, 53, "DNS"},
		{"TCP", 0, 9999, "TCP"},
		{"ICMP", 0, 0, "ICMP"},
	}
	for _, c := range cases {
		got := detectService(c.proto, c.src, c.dst)
		if got != c.want {
			t.Errorf("detectService(%q,%d,%d) = %q; want %q", c.proto, c.src, c.dst, got, c.want)
		}
	}
}

// TestIsLocalAddress verifies that IsLocalAddress reflects localAddresses map
func TestIsLocalAddress(t *testing.T) {
	nm := NewNetworkMonitor()
	nm.localAddresses = map[string]bool{"1.2.3.4":true}
	if !nm.IsLocalAddress("1.2.3.4") {
		t.Error("expected IP 1.2.3.4 to be local")
	}
	if nm.IsLocalAddress("5.6.7.8") {
		t.Error("expected IP 5.6.7.8 to be non-local")
	}
}
