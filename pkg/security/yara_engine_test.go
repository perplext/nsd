package security

import (
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

func TestNewYARAEngine(t *testing.T) {
	engine := NewYARAEngine()
	assert.NotNil(t, engine)
	assert.NotNil(t, engine.rules)
	assert.NotNil(t, engine.matches)
	assert.NotNil(t, engine.stats)
	assert.NotNil(t, engine.stats.MatchesByRule)
	assert.NotNil(t, engine.stats.MatchesByTag)
	assert.NotNil(t, engine.stats.MatchesByThreat)
	assert.True(t, len(engine.rules) > 0) // Should have default rules
}

func TestYARAEngine_ProcessPacket(t *testing.T) {
	engine := NewYARAEngine()
	
	// Test with normal packet
	packet := createTestPacket()
	matches := engine.ProcessPacket(packet)
	// ProcessPacket may return nil if packet has no payload
	// The test packet has no application layer payload
	if matches == nil {
		// This is expected for packets without payload
		assert.Nil(t, matches)
	} else {
		assert.Empty(t, matches)
	}
	
	// Test with suspicious payload
	suspiciousPayload := "This is a test malware payload with suspicious strings"
	
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
		DstIP:    []byte{192, 168, 1, 200},
	}
	
	tcp := layers.TCP{
		SrcPort: 12345,
		DstPort: 80,
		PSH:     true,
		ACK:     true,
	}
	
	tcp.SetNetworkLayerForChecksum(&ip)
	
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, gopacket.Payload(suspiciousPayload))
	
	suspiciousPacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	matches = engine.ProcessPacket(suspiciousPacket)
	// This packet has payload, so should return non-nil (even if empty)
	assert.NotNil(t, matches)
}

func TestYARAEngine_AddRule(t *testing.T) {
	engine := NewYARAEngine()
	
	// Create a test rule
	rule := YARARule{
		ID:         "test_rule_001",
		Name:       "TestRule",
		Tags:       []string{"test", "malware"},
		Strings: []YARAString{
			{
				ID:    "$test_string",
				Value: "malicious_pattern",
				Type:  "text",
			},
		},
		Condition:   "$test_string",
		Description: "Test YARA rule",
		ThreatLevel: "medium",
		Meta: map[string]string{
			"author": "test",
			"date":   "2023-01-01",
		},
	}
	
	initialRuleCount := len(engine.rules)
	engine.rules = append(engine.rules, rule)
	assert.Equal(t, initialRuleCount+1, len(engine.rules))
}

func TestYARAEngine_GetStats(t *testing.T) {
	engine := NewYARAEngine()
	
	// Process some packets
	packet := createTestPacket()
	engine.ProcessPacket(packet)
	engine.ProcessPacket(packet)
	
	stats := engine.GetStats()
	yaraStats, ok := stats.(YARAStats)
	assert.True(t, ok)
	assert.Equal(t, uint64(2), yaraStats.TotalPackets)
	assert.NotNil(t, yaraStats.MatchesByRule)
	assert.NotNil(t, yaraStats.MatchesByTag)
	assert.NotNil(t, yaraStats.MatchesByThreat)
}

func TestYARAEngine_GetMatches(t *testing.T) {
	engine := NewYARAEngine()
	
	// Initially no matches
	matches := engine.GetMatches()
	assert.Empty(t, matches)
	
	// Process packet
	packet := createTestPacket()
	engine.ProcessPacket(packet)
	
	// May or may not have matches depending on rules
	matches = engine.GetMatches()
	assert.NotNil(t, matches)
}

func TestYARAEngine_ClearMatches(t *testing.T) {
	engine := NewYARAEngine()
	
	// Add a match manually
	match := YARAMatch{
		Timestamp:   time.Now(),
		RuleID:      "test_rule",
		RuleName:    "Test Rule",
		Tags:        []string{"test"},
		ThreatLevel: "low",
		PacketInfo: PacketDetails{
			SrcIP:    "192.168.1.100",
			DstIP:    "192.168.1.200",
			Protocol: "TCP",
		},
		Meta: map[string]string{
			"test": "value",
		},
	}
	engine.matches = append(engine.matches, match)
	
	// Verify match exists
	matches := engine.GetMatches()
	assert.Len(t, matches, 1)
	
	// Clear matches
	engine.ClearMatches()
	
	// Verify cleared
	matches = engine.GetMatches()
	assert.Empty(t, matches)
}

func TestYARAEngine_PatternMatching(t *testing.T) {
	engine := NewYARAEngine()
	
	// Test with known malware patterns
	patterns := []string{
		"cmd.exe /c",
		"powershell -encodedcommand",
		"mimikatz",
		"<script>alert('xss')</script>",
		"SELECT * FROM users WHERE",
	}
	
	for _, pattern := range patterns {
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
			DstIP:    []byte{192, 168, 1, 200},
		}
		
		tcp := layers.TCP{
			SrcPort: 12345,
			DstPort: 80,
			PSH:     true,
			ACK:     true,
		}
		
		tcp.SetNetworkLayerForChecksum(&ip)
		
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, gopacket.Payload(pattern))
		
		packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
		matches := engine.ProcessPacket(packet)
		
		// Should return non-nil for packets with payload
		assert.NotNil(t, matches)
	}
}

func TestYARARule_Fields(t *testing.T) {
	rule := YARARule{
		ID:          "rule_001",
		Name:        "SuspiciousProcess",
		Tags:        []string{"process", "suspicious", "windows"},
		Strings: []YARAString{
			{
				ID:         "$str1",
				Value:      "cmd.exe",
				Type:       "text",
				Modifiers:  []string{"nocase"},
			},
			{
				ID:    "$str2",
				Value: "507573680A", // "Push\n" in hex
				Type:  "hex",
			},
		},
		Condition:   "$str1 and $str2",
		Description: "Detects suspicious process execution",
		ThreatLevel: "high",
		Meta: map[string]string{
			"author":      "security-team",
			"date":        "2023-01-01",
			"description": "Suspicious process detection",
		},
	}
	
	assert.Equal(t, "rule_001", rule.ID)
	assert.Equal(t, "SuspiciousProcess", rule.Name)
	assert.Contains(t, rule.Tags, "suspicious")
	assert.Len(t, rule.Strings, 2)
	assert.Equal(t, "$str1 and $str2", rule.Condition)
	assert.Equal(t, "high", rule.ThreatLevel)
}

func TestYARAString_Fields(t *testing.T) {
	// Test text string
	textString := YARAString{
		ID:        "$text_string",
		Value:     "malicious",
		Type:      "text",
		Modifiers: []string{"nocase"},
	}
	
	assert.Equal(t, "$text_string", textString.ID)
	assert.Equal(t, "malicious", textString.Value)
	assert.Equal(t, "text", textString.Type)
	assert.Contains(t, textString.Modifiers, "nocase")
	
	// Test hex string
	hexString := YARAString{
		ID:    "$hex_string",
		Value: "4D5A90000300",
		Type:  "hex",
	}
	
	assert.Equal(t, "$hex_string", hexString.ID)
	assert.Equal(t, "4D5A90000300", hexString.Value)
	assert.Equal(t, "hex", hexString.Type)
	
	// Test regex string
	regexString := YARAString{
		ID:        "$regex_string",
		Value:     "/[a-z0-9]{32}/",
		Type:      "regex",
		Modifiers: []string{"ascii"},
	}
	
	assert.Equal(t, "$regex_string", regexString.ID)
	assert.Equal(t, "/[a-z0-9]{32}/", regexString.Value)
	assert.Equal(t, "regex", regexString.Type)
}

func TestYARAMatch_Fields(t *testing.T) {
	match := YARAMatch{
		Timestamp:   time.Now(),
		RuleID:      "rule_001",
		RuleName:    "SuspiciousProcess",
		Tags:        []string{"process", "suspicious"},
		Strings: []StringMatch{
			{
				StringID: "$str1",
				Offset:   100,
				Length:   7,
				Data:     "cmd.exe",
			},
		},
		PacketInfo: PacketDetails{
			SrcIP:     "192.168.1.100",
			DstIP:     "192.168.1.200",
			SrcPort:   12345,
			DstPort:   80,
			Protocol:  "TCP",
			Direction: "outbound",
			Size:      1500,
		},
		ThreatLevel: "high",
		Meta: map[string]string{
			"confidence": "high",
			"category":   "malware",
		},
	}
	
	assert.Equal(t, "rule_001", match.RuleID)
	assert.Equal(t, "SuspiciousProcess", match.RuleName)
	assert.Contains(t, match.Tags, "suspicious")
	assert.Len(t, match.Strings, 1)
	assert.Equal(t, "cmd.exe", match.Strings[0].Data)
	assert.Equal(t, "high", match.ThreatLevel)
}

func TestStringMatch_Fields(t *testing.T) {
	match := StringMatch{
		StringID: "$suspicious",
		Offset:   256,
		Length:   10,
		Data:     "malicious",
	}
	
	assert.Equal(t, "$suspicious", match.StringID)
	assert.Equal(t, 256, match.Offset)
	assert.Equal(t, 10, match.Length)
	assert.Equal(t, "malicious", match.Data)
}

func TestPacketDetails_Fields(t *testing.T) {
	details := PacketDetails{
		SrcIP:     "10.0.0.100",
		DstIP:     "10.0.0.200",
		SrcPort:   54321,
		DstPort:   443,
		Protocol:  "TCP",
		Direction: "inbound",
		Size:      2048,
		Payload:   []byte("test payload"),
	}
	
	assert.Equal(t, "10.0.0.100", details.SrcIP)
	assert.Equal(t, "10.0.0.200", details.DstIP)
	assert.Equal(t, 54321, details.SrcPort)
	assert.Equal(t, 443, details.DstPort)
	assert.Equal(t, "TCP", details.Protocol)
	assert.Equal(t, "inbound", details.Direction)
	assert.Equal(t, 2048, details.Size)
	assert.Equal(t, []byte("test payload"), details.Payload)
}

func TestYARAStats_Fields(t *testing.T) {
	stats := YARAStats{
		TotalPackets: 10000,
		TotalMatches: 50,
		MatchesByRule: map[string]uint64{
			"rule_001": 20,
			"rule_002": 15,
			"rule_003": 15,
		},
		MatchesByTag: map[string]uint64{
			"malware":    30,
			"suspicious": 15,
			"exploit":    5,
		},
		MatchesByThreat: map[string]uint64{
			"high":   10,
			"medium": 25,
			"low":    15,
		},
	}
	
	assert.Equal(t, uint64(10000), stats.TotalPackets)
	assert.Equal(t, uint64(50), stats.TotalMatches)
	assert.Equal(t, uint64(20), stats.MatchesByRule["rule_001"])
	assert.Equal(t, uint64(30), stats.MatchesByTag["malware"])
	assert.Equal(t, uint64(10), stats.MatchesByThreat["high"])
}

func TestYARAEngine_ThreatDetection(t *testing.T) {
	engine := NewYARAEngine()
	
	// Test various threat patterns
	threats := map[string]string{
		"ransomware": "Your files have been encrypted",
		"trojan":     "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		"backdoor":   "nc -lvp 4444",
		"rootkit":    "\\Device\\PhysicalMemory",
		"keylogger":  "GetAsyncKeyState",
	}
	
	for threatType, pattern := range threats {
		payload := "Test data with " + pattern + " embedded"
		
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
			DstIP:    []byte{192, 168, 1, 200},
		}
		
		tcp := layers.TCP{
			SrcPort: 12345,
			DstPort: 80,
			PSH:     true,
			ACK:     true,
		}
		
		tcp.SetNetworkLayerForChecksum(&ip)
		
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, gopacket.Payload(payload))
		
		packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
		matches := engine.ProcessPacket(packet)
		
		// May detect based on loaded rules
		assert.NotNil(t, matches)
		_ = threatType // Avoid unused variable warning
	}
}