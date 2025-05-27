package security

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

func TestNewSuricataEngine(t *testing.T) {
	// Test with EVE format disabled
	engine := NewSuricataEngine(false)
	assert.NotNil(t, engine)
	assert.NotNil(t, engine.rules)
	assert.NotNil(t, engine.alerts)
	assert.NotNil(t, engine.flowTable)
	assert.False(t, engine.eveFormat)
	assert.True(t, len(engine.rules) > 0) // Should have default rules

	// Test with EVE format enabled
	engineEVE := NewSuricataEngine(true)
	assert.True(t, engineEVE.eveFormat)
}

func TestSuricataEngine_ProcessPacket(t *testing.T) {
	engine := NewSuricataEngine(false)
	
	// Test with normal packet
	packet := createTestPacket()
	alerts := engine.ProcessPacket(packet)
	assert.NotNil(t, alerts)
	
	// Test with HTTP packet
	httpPayload := "GET /malicious.exe HTTP/1.1\r\nHost: badsite.com\r\nUser-Agent: Malicious/1.0\r\n\r\n"
	
	eth := layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{192, 168, 1, 100},
		DstIP:    []byte{10, 0, 0, 1},
	}
	
	tcp := layers.TCP{
		SrcPort: 54321,
		DstPort: 80,
		PSH:     true,
		ACK:     true,
	}
	
	tcp.SetNetworkLayerForChecksum(&ip)
	
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, gopacket.Payload(httpPayload))
	
	httpPacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	alerts = engine.ProcessPacket(httpPacket)
	
	// May or may not generate alerts based on rules
	assert.NotNil(t, alerts)
}

func TestSuricataEngine_AddRule(t *testing.T) {
	engine := NewSuricataEngine(false)
	
	// Test adding a rule
	rule := SuricataRule{
		ID:        1,
		Action:    "alert",
		Protocol:  "http",
		SrcIP:     "$HOME_NET",
		SrcPort:   "any",
		Direction: "->",
		DstIP:     "$EXTERNAL_NET",
		DstPort:   "any",
		Message:   "ET MALWARE Suspicious User-Agent",
		Classtype: "trojan-activity",
		SID:       2100001,
		Rev:       1,
		Priority:  1,
		Options: map[string][]string{
			"msg":      {"ET MALWARE Suspicious User-Agent"},
			"flow":     {"established", "to_server"},
			"content":  {"Malicious"},
		},
	}
	
	initialRuleCount := len(engine.rules)
	engine.rules = append(engine.rules, rule)
	assert.Equal(t, initialRuleCount+1, len(engine.rules))
}

func TestSuricataEngine_GetStats(t *testing.T) {
	engine := NewSuricataEngine(false)
	
	// Process some packets
	packet := createTestPacket()
	engine.ProcessPacket(packet)
	engine.ProcessPacket(packet)
	
	stats := engine.GetStats()
	suricataStats, ok := stats.(SuricataStats)
	assert.True(t, ok)
	assert.Equal(t, uint64(2), suricataStats.TotalPackets)
	assert.NotNil(t, suricataStats.AlertsByRule)
	assert.NotNil(t, suricataStats.AlertsBySeverity)
}

func TestSuricataEngine_ClearAlerts(t *testing.T) {
	engine := NewSuricataEngine(false)
	
	// Manually add alert
	alert := SuricataAlert{
		Timestamp: time.Now(),
		EventType: "alert",
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		Alert: &AlertInfo{
			Action:      "allowed",
			SignatureID: 2100001,
			Signature:   "Test alert",
			Category:    "test-category",
			Severity:    1,
		},
	}
	engine.alerts = append(engine.alerts, alert)
	
	// Verify alert exists
	alerts := engine.GetAlerts()
	assert.Len(t, alerts, 1)
	
	// Clear alerts
	engine.ClearAlerts()
	
	// Verify cleared
	alerts = engine.GetAlerts()
	assert.Empty(t, alerts)
}


func TestSuricataEngine_DNSProcessing(t *testing.T) {
	engine := NewSuricataEngine(false)
	
	// Create DNS query packet
	dnsPacket := createDNSPacket("suspicious-domain.com", layers.DNSTypeA)
	alerts := engine.ProcessPacket(dnsPacket)
	
	assert.NotNil(t, alerts)
	
	// Create DNS response
	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e},
		DstMAC:       net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		EthernetType: layers.EthernetTypeIPv4,
	}
	
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IP{8, 8, 8, 8},
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
		AA:      false,
		TC:      false,
		RD:      true,
		RA:      true,
		ANCount: 1,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte("suspicious-domain.com"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		},
		Answers: []layers.DNSResourceRecord{
			{
				Name:  []byte("suspicious-domain.com"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				TTL:   300,
				IP:    net.IP{1, 2, 3, 4},
			},
		},
	}
	
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	udp.SetNetworkLayerForChecksum(&ip)
	gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, &dns)
	
	dnsResponse := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	alerts = engine.ProcessPacket(dnsResponse)
	
	assert.NotNil(t, alerts)
}

func TestSuricataStats_Fields(t *testing.T) {
	stats := SuricataStats{
		TotalPackets:     5000,
		TotalAlerts:      100,
		TotalFlows:       200,
		ActiveFlows:      50,
		ClosedFlows:      150,
		AlertsByRule:     map[int]uint64{
			2100001: 20,
			2100002: 30,
			2100003: 50,
		},
		AlertsBySeverity: map[int]uint64{
			1: 10,
			2: 30,
			3: 60,
		},
		ProtocolStats: map[string]uint64{
			"tcp": 3000,
			"udp": 1500,
			"icmp": 500,
		},
	}
	
	assert.Equal(t, uint64(5000), stats.TotalPackets)
	assert.Equal(t, uint64(100), stats.TotalAlerts)
	assert.Equal(t, uint64(200), stats.TotalFlows)
	assert.Equal(t, uint64(50), stats.ActiveFlows)
	assert.Equal(t, uint64(150), stats.ClosedFlows)
	assert.Equal(t, uint64(20), stats.AlertsByRule[2100001])
	assert.Equal(t, uint64(3000), stats.ProtocolStats["tcp"])
}

func TestSuricataAlert_EVEFormat(t *testing.T) {
	// engine := NewSuricataEngine(true) // Not used in this test
	
	alert := SuricataAlert{
		Timestamp: time.Now(),
		FlowID:    "12345",
		EventType: "alert",
		SrcIP:     "192.168.1.100",
		SrcPort:   54321,
		DstIP:     "10.0.0.1",
		DstPort:   80,
		Protocol:  "TCP",
		Alert: &AlertInfo{
			Action:      "allowed",
			GID:         1,
			SignatureID: 2100001,
			Rev:         1,
			Signature:   "ET MALWARE Test",
			Category:    "trojan-activity",
			Severity:    1,
		},
		HTTP: map[string]interface{}{
			"hostname": "malicious.com",
			"url":      "/bad.exe",
			"method":   "GET",
		},
	}
	
	// Verify EVE format fields
	assert.Equal(t, "alert", alert.EventType)
	assert.NotNil(t, alert.Alert)
	assert.NotNil(t, alert.HTTP)
	assert.Equal(t, "malicious.com", alert.HTTP["hostname"])
}

func TestThresholdConfig_Fields(t *testing.T) {
	threshold := ThresholdConfig{
		Type:     "limit",
		Track:    "by_src",
		Count:    5,
		Seconds:  60,
	}
	
	assert.Equal(t, "limit", threshold.Type)
	assert.Equal(t, "by_src", threshold.Track)
	assert.Equal(t, 5, threshold.Count)
	assert.Equal(t, 60, threshold.Seconds)
}

func TestDetectionConfig_Fields(t *testing.T) {
	detection := DetectionConfig{
		FastPattern: true,
		Nocase:      true,
		Depth:       100,
		Offset:      0,
		Distance:    0,
		Within:      50,
	}
	
	assert.True(t, detection.FastPattern)
	assert.True(t, detection.Nocase)
	assert.Equal(t, 100, detection.Depth)
	assert.Equal(t, 50, detection.Within)
}

func TestSuricataPacketInfo_Fields(t *testing.T) {
	packetInfo := SuricataPacketInfo{
		Linktype:  1,
		Direction: "to_server",
	}
	
	assert.Equal(t, 1, packetInfo.Linktype)
	assert.Equal(t, "to_server", packetInfo.Direction)
}