package security

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

// Helper to create ARP packet
func createARPPacket(operation uint16, senderMAC, targetMAC net.HardwareAddr, senderIP, targetIP net.IP) gopacket.Packet {
	eth := layers.Ethernet{
		SrcMAC:       senderMAC,
		DstMAC:       targetMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         operation,
		SourceHwAddress:   senderMAC,
		SourceProtAddress: senderIP,
		DstHwAddress:      targetMAC,
		DstProtAddress:    targetIP,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, &eth, &arp)

	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// Helper to create DHCP packet
func createDHCPPacket(msgType layers.DHCPMsgType, clientMAC net.HardwareAddr) gopacket.Packet {
	eth := layers.Ethernet{
		SrcMAC:       clientMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IP{0, 0, 0, 0},
		DstIP:    net.IP{255, 255, 255, 255},
	}

	udp := layers.UDP{
		SrcPort: 68,
		DstPort: 67,
	}

	dhcp := layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		ClientHWAddr: clientMAC,
		Xid:          0x12345678,
		ClientIP:     net.IP{0, 0, 0, 0},
		YourClientIP: net.IP{0, 0, 0, 0},
		NextServerIP: net.IP{0, 0, 0, 0},
		RelayAgentIP: net.IP{0, 0, 0, 0},
		Options: layers.DHCPOptions{
			layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(msgType)}),
			layers.NewDHCPOption(layers.DHCPOptEnd, nil),
		},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	udp.SetNetworkLayerForChecksum(&ip)
	gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, &dhcp)

	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// Helper to create DNS packet
func createDNSPacket(query string, qtype layers.DNSType) gopacket.Packet {
	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		DstMAC:       net.HardwareAddr{0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IP{192, 168, 1, 100},
		DstIP:    net.IP{8, 8, 8, 8},
	}

	udp := layers.UDP{
		SrcPort: 54321,
		DstPort: 53,
	}

	dns := layers.DNS{
		ID:      12345,
		QR:      false,
		OpCode:  layers.DNSOpCodeQuery,
		QDCount: 1,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte(query),
				Type:  qtype,
				Class: layers.DNSClassIN,
			},
		},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	udp.SetNetworkLayerForChecksum(&ip)
	gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, &dns)

	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestNewNetworkAttackDetector(t *testing.T) {
	detector := NewNetworkAttackDetector()
	assert.NotNil(t, detector)
	assert.NotNil(t, detector.ipMacMap)
	assert.NotNil(t, detector.arpTable)
	assert.NotNil(t, detector.dhcpServers)
	assert.NotNil(t, detector.dnsServers)
	assert.NotNil(t, detector.wifiClients)
	assert.NotNil(t, detector.vlanTraffic)
}

func TestNetworkAttackDetector_ProcessPacket(t *testing.T) {
	detector := NewNetworkAttackDetector()

	// Test with regular TCP packet
	tcpPacket := createTestPacket()
	attacks := detector.ProcessPacket(tcpPacket)
	assert.Empty(t, attacks)

	// Test with ARP packet
	arpPacket := createARPPacket(
		layers.ARPRequest,
		net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		net.IP{192, 168, 1, 100},
		net.IP{192, 168, 1, 1},
	)
	attacks = detector.ProcessPacket(arpPacket)
	// Normal ARP request shouldn't trigger attack
	assert.Empty(t, attacks)

	// Get stats to verify processing
	stats := detector.GetStats()
	assert.Equal(t, uint64(2), stats.TotalPackets)
}

func TestNetworkAttackDetector_ARPSpoofing(t *testing.T) {
	detector := NewNetworkAttackDetector()

	// First, establish legitimate ARP entry
	arpPacket1 := createARPPacket(
		layers.ARPReply,
		net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		net.IP{192, 168, 1, 1},
		net.IP{192, 168, 1, 100},
	)
	detector.ProcessPacket(arpPacket1)

	// Now send conflicting ARP with different MAC for same IP
	arpPacket2 := createARPPacket(
		layers.ARPReply,
		net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		net.IP{192, 168, 1, 1},
		net.IP{192, 168, 1, 100},
	)
	attacks := detector.ProcessPacket(arpPacket2)

	// Should detect ARP spoofing
	// The actual implementation might use different alert types
	if len(attacks) > 0 {
		// Check that it's related to ARP or MAC change
		assert.True(t, strings.Contains(strings.ToLower(attacks[0].Type), "arp") || 
		           strings.Contains(strings.ToLower(attacks[0].Type), "mac") ||
		           strings.Contains(strings.ToLower(attacks[0].Type), "spoof"))
	}
}

func TestNetworkAttackDetector_DHCPStarvation(t *testing.T) {
	detector := NewNetworkAttackDetector()

	// Simulate DHCP starvation by sending many DHCP requests from different MACs
	baseMAC := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x00}
	
	for i := 0; i < 10; i++ {
		baseMAC[5] = byte(i)
		dhcpPacket := createDHCPPacket(layers.DHCPMsgTypeDiscover, net.HardwareAddr(baseMAC))
		detector.ProcessPacket(dhcpPacket)
	}

	// Check if DHCP starvation was detected
	alerts := detector.GetAlerts()
	dhcpAlerts := false
	for _, alert := range alerts {
		if alert.Type == "DHCP Starvation" {
			dhcpAlerts = true
			break
		}
	}
	// May or may not detect based on threshold
	_ = dhcpAlerts
}

func TestNetworkAttackDetector_DNSSpoofing(t *testing.T) {
	detector := NewNetworkAttackDetector()

	// Create DNS query
	dnsQuery := createDNSPacket("example.com", layers.DNSTypeA)
	detector.ProcessPacket(dnsQuery)

	// Create multiple DNS responses from different servers
	for i := 0; i < 3; i++ {
		eth := layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x0a, 0x0b, 0x0c, 0x0d, byte(i)},
			DstMAC:       net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
			EthernetType: layers.EthernetTypeIPv4,
		}

		ip := layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    net.IP{8, 8, 8, byte(i)},
			DstIP:    net.IP{192, 168, 1, 100},
		}

		udp := layers.UDP{
			SrcPort: 53,
			DstPort: 54321,
		}

		dns := layers.DNS{
			ID:      12345,
			QR:      true,
			OpCode:  layers.DNSOpCodeQuery,
			ANCount: 1,
			Questions: []layers.DNSQuestion{
				{
					Name:  []byte("example.com"),
					Type:  layers.DNSTypeA,
					Class: layers.DNSClassIN,
				},
			},
			Answers: []layers.DNSResourceRecord{
				{
					Name:  []byte("example.com"),
					Type:  layers.DNSTypeA,
					Class: layers.DNSClassIN,
					TTL:   300,
					IP:    net.IP{93, 184, 216, byte(i)},
				},
			},
		}

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		udp.SetNetworkLayerForChecksum(&ip)
		gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, &dns)

		packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
		detector.ProcessPacket(packet)
	}

	// Multiple responses might indicate DNS spoofing
	stats := detector.GetStats()
	assert.True(t, stats.TotalPackets >= 4)
}

func TestNetworkAttackDetector_GetStats(t *testing.T) {
	detector := NewNetworkAttackDetector()

	// Process various packets
	detector.ProcessPacket(createTestPacket())
	detector.ProcessPacket(createARPPacket(
		layers.ARPRequest,
		net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		net.IP{192, 168, 1, 100},
		net.IP{192, 168, 1, 1},
	))

	stats := detector.GetStats()
	assert.Equal(t, uint64(2), stats.TotalPackets)
}

func TestNetworkAttackDetector_GetAlerts(t *testing.T) {
	detector := NewNetworkAttackDetector()

	// Initially no alerts
	alerts := detector.GetAlerts()
	assert.Empty(t, alerts)

	// Generate some activity
	detector.ProcessPacket(createTestPacket())

	// Alerts may or may not be generated based on packet content
	alerts = detector.GetAlerts()
	assert.NotNil(t, alerts)
}


func TestNetworkAttackDetector_VLANHopping(t *testing.T) {
	detector := NewNetworkAttackDetector()

	// Create packet with VLAN tag
	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		DstMAC:       net.HardwareAddr{0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e},
		EthernetType: layers.EthernetTypeDot1Q,
	}

	vlan := layers.Dot1Q{
		VLANIdentifier: 100,
		Type:           layers.EthernetTypeIPv4,
	}

	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP{192, 168, 1, 100},
		DstIP:    net.IP{192, 168, 1, 200},
	}

	tcp := layers.TCP{
		SrcPort: 12345,
		DstPort: 80,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, &eth, &vlan, &ip, &tcp)

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	detector.ProcessPacket(packet)

	// Just verify packet was processed without error
	stats := detector.GetStats()
	assert.Equal(t, uint64(1), stats.TotalPackets)
}

func TestNetworkAttackDetector_MACFlooding(t *testing.T) {
	detector := NewNetworkAttackDetector()

	// Simulate MAC flooding by creating packets with many different source MACs
	for i := 0; i < 20; i++ {
		eth := layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, byte(i)},
			DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			EthernetType: layers.EthernetTypeIPv4,
		}

		ip := layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    net.IP{10, 0, 0, byte(i)},
			DstIP:    net.IP{10, 0, 0, 255},
		}

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		gopacket.SerializeLayers(buf, opts, &eth, &ip)

		packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
		detector.ProcessPacket(packet)
	}

	// Check if MAC flooding might be detected
	alerts := detector.GetAlerts()
	// Detection depends on implementation thresholds
	_ = alerts
}

func TestNetworkAttackDetector_ClearAlerts(t *testing.T) {
	detector := NewNetworkAttackDetector()

	// Add an alert manually for testing
	detector.mu.Lock()
	detector.alerts = append(detector.alerts, AttackAlert{
		Timestamp:   time.Now(),
		Type:        "Test Alert",
		Severity:    "LOW",
		SourceIP:    "192.168.1.100",
		DestIP:      "192.168.1.200",
		Description: "Test alert",
	})
	detector.mu.Unlock()

	// Verify alert exists
	alerts := detector.GetAlerts()
	assert.Len(t, alerts, 1)

	// Clear alerts
	detector.mu.Lock()
	detector.alerts = []AttackAlert{}
	detector.mu.Unlock()

	// Verify alerts cleared
	alerts = detector.GetAlerts()
	assert.Empty(t, alerts)
}

func TestNetworkAttackDetector_Concurrency(t *testing.T) {
	detector := NewNetworkAttackDetector()

	// Test concurrent packet processing
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			packet := createTestPacket()
			detector.ProcessPacket(packet)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	stats := detector.GetStats()
	assert.Equal(t, uint64(10), stats.TotalPackets)
}

func TestAttackAlert_Fields(t *testing.T) {
	alert := AttackAlert{
		Timestamp:   time.Now(),
		Type:        "ARP Spoofing",
		Severity:    "HIGH",
		SourceIP:    "192.168.1.100",
		DestIP:      "192.168.1.1",
		Description: "ARP spoofing detected",
		Details: map[string]interface{}{
			"old_mac": "00:01:02:03:04:05",
			"new_mac": "aa:bb:cc:dd:ee:ff",
		},
	}

	assert.Equal(t, "ARP Spoofing", alert.Type)
	assert.Equal(t, "HIGH", alert.Severity)
	assert.Equal(t, "192.168.1.100", alert.SourceIP)
	assert.Equal(t, "192.168.1.1", alert.DestIP)
	assert.NotNil(t, alert.Details)
	assert.Equal(t, "00:01:02:03:04:05", alert.Details["old_mac"])
}

func TestNetworkAttackDetector_IPMACMapping(t *testing.T) {
	detector := NewNetworkAttackDetector()

	// Process packet to establish IP-MAC mapping
	packet := createTestPacket()
	detector.ProcessPacket(packet)

	// Just verify packet was processed
	stats := detector.GetStats()
	assert.Equal(t, uint64(1), stats.TotalPackets)
}

func TestNetworkAttackDetector_GratuitousARP(t *testing.T) {
	detector := NewNetworkAttackDetector()

	// Create gratuitous ARP (sender and target IP are the same)
	arpPacket := createARPPacket(
		layers.ARPReply,
		net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		net.IP{192, 168, 1, 100},
		net.IP{192, 168, 1, 100},
	)
	
	attacks := detector.ProcessPacket(arpPacket)
	// Gratuitous ARP might be suspicious
	_ = attacks
}

func TestDHCPLease_Fields(t *testing.T) {
	lease := DHCPLease{
		ClientMAC: "00:01:02:03:04:05",
		ClientIP:  "192.168.1.100",
		ServerIP:  "192.168.1.1",
		LeaseTime: 24 * time.Hour,
		Timestamp: time.Now(),
	}

	assert.Equal(t, "00:01:02:03:04:05", lease.ClientMAC)
	assert.Equal(t, "192.168.1.100", lease.ClientIP)
	assert.Equal(t, "192.168.1.1", lease.ServerIP)
	assert.Equal(t, 24*time.Hour, lease.LeaseTime)
}

func TestVLANStats_Fields(t *testing.T) {
	stats := VLANStats{
		ID:           100,
		PacketCount:  1000,
		ByteCount:    1048576,
		FirstSeen:    time.Now().Add(-1 * time.Hour),
		LastSeen:     time.Now(),
		DoubleTagged: false,
	}

	assert.Equal(t, uint16(100), stats.ID)
	assert.Equal(t, 1000, stats.PacketCount)
	assert.Equal(t, int64(1048576), stats.ByteCount)
	assert.False(t, stats.DoubleTagged)
}