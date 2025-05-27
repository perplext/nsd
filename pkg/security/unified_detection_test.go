package security

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create a test packet
func createTestPacket() gopacket.Packet {
	// Create a simple TCP packet
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
		SYN:     true,
	}
	
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp)
	
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestNewUnifiedDetectionEngine(t *testing.T) {
	// Test with no engines enabled
	config := UnifiedConfig{
		EnabledEngines: []string{},
		OutputFormat:   "json",
	}
	ude := NewUnifiedDetectionEngine(config)
	assert.NotNil(t, ude)
	assert.Empty(t, ude.engines)
	assert.Empty(t, ude.alerts)
	assert.NotNil(t, ude.correlator)

	// Test with all engines enabled
	config = UnifiedConfig{
		EnabledEngines: []string{"snort", "suricata", "zeek", "yara", "sigma", "network_attacks"},
		OutputFormat:   "json",
	}
	ude = NewUnifiedDetectionEngine(config)
	assert.NotNil(t, ude)
	assert.Len(t, ude.engines, 6)
	assert.NotNil(t, ude.snortEngine)
	assert.NotNil(t, ude.suricataEngine)
	assert.NotNil(t, ude.zeekEngine)
	assert.NotNil(t, ude.yaraEngine)
	assert.NotNil(t, ude.sigmaEngine)
	assert.NotNil(t, ude.networkAttackDetector)
}

func TestUnifiedDetectionEngine_ProcessPacket(t *testing.T) {
	config := UnifiedConfig{
		EnabledEngines: []string{"snort", "suricata"},
		OutputFormat:   "json",
	}
	ude := NewUnifiedDetectionEngine(config)
	
	packet := createTestPacket()
	alerts := ude.ProcessPacket(packet)
	
	// Should return empty alerts for a normal packet
	assert.NotNil(t, alerts)
	
	// Check stats were updated
	stats := ude.GetStats()
	assert.NotNil(t, stats)
	assert.Equal(t, uint64(1), stats.TotalPackets)
}

func TestUnifiedDetectionEngine_NormalizeAlerts(t *testing.T) {
	config := UnifiedConfig{
		EnabledEngines: []string{},
		OutputFormat:   "json",
	}
	ude := NewUnifiedDetectionEngine(config)

	// Test Snort alert normalization
	snortAlert := SnortAlert{
		Timestamp:  time.Now(),
		RuleID:     1,
		SID:        2001234,
		Priority:   1,
		Message:    "Test Snort Alert",
		SrcIP:      "192.168.1.100",
		DstIP:      "192.168.1.200",
		SrcPort:    12345,
		DstPort:    80,
		Protocol:   "TCP",
		Classtype:  "attempted-admin",
	}
	
	unified := ude.normalizeSnortAlert(snortAlert)
	assert.Equal(t, "snort", unified.Engine)
	assert.Equal(t, SeverityCritical, unified.Severity)
	assert.Equal(t, "ids_alert", unified.Type)
	assert.Equal(t, "SID:2001234", unified.Signature)
	assert.Equal(t, "Test Snort Alert", unified.Message)
	assert.Equal(t, "192.168.1.100", unified.SourceIP)
	assert.Equal(t, "192.168.1.200", unified.DestIP)

	// Test Suricata alert normalization
	suricataAlert := SuricataAlert{
		Timestamp: time.Now(),
		EventType: "alert",
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   443,
		DstPort:   54321,
		Protocol:  "TCP",
		Alert: &AlertInfo{
			Action:      "allowed",
			SignatureID: 2100001,
			Signature:   "ET MALWARE Suspicious User-Agent",
			Category:    "A Network Trojan was detected",
			Severity:    1,
		},
	}
	
	unified = ude.normalizeSuricataAlert(suricataAlert)
	assert.Equal(t, "suricata", unified.Engine)
	assert.Equal(t, SeverityCritical, unified.Severity)
	assert.Equal(t, "ids_alert", unified.Type)

	// Test YARA match normalization
	yaraMatch := YARAMatch{
		Timestamp: time.Now(),
		RuleName:  "MalwareRule",
		Tags:      []string{"ransomware", "critical"},
		Meta: map[string]string{
			"author":      "security-team",
			"description": "Ransomware detection",
		},
		PacketInfo: PacketDetails{
			SrcIP:    "172.16.0.100",
			DstIP:    "172.16.0.200",
			Protocol: "TCP",
		},
	}
	
	unified = ude.normalizeYARAMatch(yaraMatch)
	assert.Equal(t, "yara", unified.Engine)
	assert.Equal(t, SeverityCritical, unified.Severity)
	assert.Equal(t, "malware_detection", unified.Type)
	assert.Equal(t, "MalwareRule", unified.Signature)

	// Test Sigma alert normalization
	sigmaAlert := SigmaAlert{
		Timestamp:  time.Now(),
		RuleID:     "rule-001",
		RuleTitle:  "Suspicious Process Creation",
		Level:      "HIGH",
		Message:    "Detected suspicious process",
		MatchedFields: map[string]interface{}{
			"process": "cmd.exe",
			"parent":  "powershell.exe",
		},
	}
	
	unified = ude.normalizeSigmaAlert(sigmaAlert)
	assert.Equal(t, "sigma", unified.Engine)
	assert.Equal(t, SeverityHigh, unified.Severity)
	assert.Equal(t, "security_event", unified.Type)

	// Test Network Attack normalization
	attack := AttackAlert{
		Timestamp:   time.Now(),
		Type:        "DDoS",
		Severity:    "CRITICAL",
		SourceIP:    "1.2.3.4",
		DestIP:      "5.6.7.8",
		Description: "DDoS attack detected",
		Details: map[string]interface{}{
			"packets_per_second": 10000,
		},
	}
	
	unified = ude.normalizeNetworkAttack(attack)
	assert.Equal(t, "network_attacks", unified.Engine)
	assert.Equal(t, SeverityCritical, unified.Severity)
	assert.Equal(t, "network_attack", unified.Type)
}

func TestUnifiedDetectionEngine_MapSeverities(t *testing.T) {
	config := UnifiedConfig{}
	ude := NewUnifiedDetectionEngine(config)

	// Test Snort priority mapping
	assert.Equal(t, SeverityCritical, ude.mapSnortPriority(1))
	assert.Equal(t, SeverityHigh, ude.mapSnortPriority(2))
	assert.Equal(t, SeverityMedium, ude.mapSnortPriority(3))
	assert.Equal(t, SeverityLow, ude.mapSnortPriority(4))
	assert.Equal(t, SeverityLow, ude.mapSnortPriority(5))

	// Test Suricata severity mapping
	assert.Equal(t, SeverityCritical, ude.mapSuricataSeverity(1))
	assert.Equal(t, SeverityHigh, ude.mapSuricataSeverity(2))
	assert.Equal(t, SeverityMedium, ude.mapSuricataSeverity(3))
	assert.Equal(t, SeverityLow, ude.mapSuricataSeverity(4))

	// Test Zeek event severity mapping
	assert.Equal(t, SeverityCritical, ude.mapZeekEventSeverity("exploit_attempt"))
	assert.Equal(t, SeverityCritical, ude.mapZeekEventSeverity("malware_detected"))
	assert.Equal(t, SeverityHigh, ude.mapZeekEventSeverity("scan_detected"))
	assert.Equal(t, SeverityHigh, ude.mapZeekEventSeverity("bruteforce_attempt"))
	assert.Equal(t, SeverityMedium, ude.mapZeekEventSeverity("dns_query"))

	// Test YARA tags mapping
	assert.Equal(t, SeverityCritical, ude.mapYARATags([]string{"critical"}))
	assert.Equal(t, SeverityCritical, ude.mapYARATags([]string{"apt", "advanced"}))
	assert.Equal(t, SeverityCritical, ude.mapYARATags([]string{"ransomware"}))
	assert.Equal(t, SeverityHigh, ude.mapYARATags([]string{"malware"}))
	assert.Equal(t, SeverityHigh, ude.mapYARATags([]string{"trojan"}))
	assert.Equal(t, SeverityMedium, ude.mapYARATags([]string{"suspicious"}))
	assert.Equal(t, SeverityLow, ude.mapYARATags([]string{"info", "test"}))
}

func TestUnifiedDetectionEngine_Stats(t *testing.T) {
	config := UnifiedConfig{
		EnabledEngines: []string{"snort"},
		OutputFormat:   "json",
	}
	ude := NewUnifiedDetectionEngine(config)

	// Initial stats
	stats := ude.GetStats()
	assert.Equal(t, uint64(0), stats.TotalPackets)
	assert.Equal(t, uint64(0), stats.TotalAlerts)
	assert.NotNil(t, stats.AlertsByEngine)
	assert.NotNil(t, stats.AlertsBySeverity)
	assert.NotNil(t, stats.AlertsByType)

	// Process packet to update stats
	packet := createTestPacket()
	ude.ProcessPacket(packet)

	stats = ude.GetStats()
	assert.Equal(t, uint64(1), stats.TotalPackets)
}

func TestUnifiedDetectionEngine_AlertManagement(t *testing.T) {
	config := UnifiedConfig{
		EnabledEngines: []string{},
		OutputFormat:   "json",
	}
	ude := NewUnifiedDetectionEngine(config)

	// Manually add some alerts for testing
	alert1 := UnifiedAlert{
		ID:        "test-1",
		Timestamp: time.Now(),
		Engine:    "test",
		Severity:  SeverityHigh,
		Type:      "test_alert",
		Signature: "TEST-001",
		Message:   "Test alert 1",
	}
	
	alert2 := UnifiedAlert{
		ID:        "test-2",
		Timestamp: time.Now(),
		Engine:    "test",
		Severity:  SeverityMedium,
		Type:      "test_alert",
		Signature: "TEST-002",
		Message:   "Test alert 2",
	}

	ude.mu.Lock()
	ude.alerts = append(ude.alerts, alert1, alert2)
	ude.mu.Unlock()

	// Test GetAlerts
	alerts := ude.GetAlerts()
	assert.Len(t, alerts, 2)
	assert.Equal(t, "test-1", alerts[0].ID)
	assert.Equal(t, "test-2", alerts[1].ID)

	// Test ClearAlerts
	ude.ClearAlerts()
	alerts = ude.GetAlerts()
	assert.Empty(t, alerts)
}

func TestUnifiedDetectionEngine_ExportAlerts(t *testing.T) {
	config := UnifiedConfig{
		EnabledEngines: []string{},
		OutputFormat:   "json",
	}
	ude := NewUnifiedDetectionEngine(config)

	// Add test alert
	alert := UnifiedAlert{
		ID:         "test-1",
		Timestamp:  time.Now(),
		Engine:     "test",
		Severity:   SeverityHigh,
		Type:       "test_alert",
		Signature:  "TEST-001",
		Message:    "Test alert",
		SourceIP:   "192.168.1.100",
		DestIP:     "192.168.1.200",
		SourcePort: 12345,
		DestPort:   80,
		Protocol:   "TCP",
	}

	ude.mu.Lock()
	ude.alerts = append(ude.alerts, alert)
	ude.mu.Unlock()

	// Test JSON export
	data, err := ude.ExportAlerts("json")
	require.NoError(t, err)
	assert.NotEmpty(t, data)
	
	var exportedAlerts []UnifiedAlert
	err = json.Unmarshal(data, &exportedAlerts)
	require.NoError(t, err)
	assert.Len(t, exportedAlerts, 1)
	assert.Equal(t, "test-1", exportedAlerts[0].ID)

	// Test CEF export
	data, err = ude.ExportAlerts("cef")
	require.NoError(t, err)
	assert.NotEmpty(t, data)
	assert.Contains(t, string(data), "CEF:0|NetMon|UnifiedDetection")
	assert.Contains(t, string(data), "TEST-001")

	// Test LEEF export
	data, err = ude.ExportAlerts("leef")
	require.NoError(t, err)
	assert.NotEmpty(t, data)
	assert.Contains(t, string(data), "LEEF:1.0|NetMon|UnifiedDetection")

	// Test Syslog export
	data, err = ude.ExportAlerts("syslog")
	require.NoError(t, err)
	assert.NotEmpty(t, data)
	assert.Contains(t, string(data), "netmon[unified]")

	// Test unsupported format
	_, err = ude.ExportAlerts("xml")
	assert.Error(t, err)
}

func TestUnifiedDetectionEngine_HelperFunctions(t *testing.T) {
	config := UnifiedConfig{}
	ude := NewUnifiedDetectionEngine(config)

	// Test isAlertableZeekEvent
	assert.True(t, ude.isAlertableZeekEvent("connection_established"))
	assert.True(t, ude.isAlertableZeekEvent("dns_query"))
	assert.True(t, ude.isAlertableZeekEvent("http_request"))
	assert.True(t, ude.isAlertableZeekEvent("ssl_certificate"))
	assert.True(t, ude.isAlertableZeekEvent("scan_detected"))
	assert.False(t, ude.isAlertableZeekEvent("random_event"))

	// Test severityToInt
	assert.Equal(t, 1, ude.severityToInt(SeverityCritical))
	assert.Equal(t, 2, ude.severityToInt(SeverityHigh))
	assert.Equal(t, 3, ude.severityToInt(SeverityMedium))
	assert.Equal(t, 4, ude.severityToInt(SeverityLow))
	assert.Equal(t, 5, ude.severityToInt("unknown"))

	// Test convertStringMapToInterface
	stringMap := map[string]string{
		"key1": "value1",
		"key2": "value2",
	}
	interfaceMap := convertStringMapToInterface(stringMap)
	assert.Len(t, interfaceMap, 2)
	assert.Equal(t, "value1", interfaceMap["key1"])
	assert.Equal(t, "value2", interfaceMap["key2"])
}

func TestAlertCorrelator(t *testing.T) {
	rules := []CorrelationRule{
		{
			ID:          "rule1",
			Name:        "Test Rule",
			Description: "Test correlation rule",
			TimeWindow:  5 * time.Minute,
		},
	}

	correlator := NewAlertCorrelator(rules)
	assert.NotNil(t, correlator)
	assert.Len(t, correlator.rules, 1)
	assert.NotNil(t, correlator.alertBuffer)

	// Test CorrelateAlerts (currently just returns input)
	alerts := []UnifiedAlert{
		{ID: "alert1"},
		{ID: "alert2"},
	}
	
	correlated := correlator.CorrelateAlerts(alerts)
	assert.Equal(t, alerts, correlated)
}

func TestUnifiedDetectionEngine_EngineWrappers(t *testing.T) {
	// Test SnortEngineWrapper
	snortEngine := NewSnortEngine()
	wrapper := &SnortEngineWrapper{engine: snortEngine}
	
	packet := createTestPacket()
	result := wrapper.ProcessPacket(packet)
	// Result is []SnortAlert which may be empty
	alerts, ok := result.([]SnortAlert)
	assert.True(t, ok)
	assert.NotNil(t, alerts)
	
	stats := wrapper.GetStats()
	assert.NotNil(t, stats)
	
	// Should not panic
	wrapper.ClearAlerts()

	// Test SuricataEngineWrapper
	suricataEngine := NewSuricataEngine(false)
	suricataWrapper := &SuricataEngineWrapper{engine: suricataEngine}
	
	result = suricataWrapper.ProcessPacket(packet)
	// Result is []SuricataAlert which may be empty
	sAlerts, ok := result.([]SuricataAlert)
	assert.True(t, ok)
	assert.NotNil(t, sAlerts)
	
	stats = suricataWrapper.GetStats()
	assert.NotNil(t, stats)
	
	suricataWrapper.ClearAlerts()

	// Test NetworkAttackWrapper
	detector := NewNetworkAttackDetector()
	attackWrapper := &NetworkAttackWrapper{detector: detector}
	
	result = attackWrapper.ProcessPacket(packet)
	// Result is []AttackAlert which may be empty
	aAlerts, ok := result.([]AttackAlert)
	assert.True(t, ok)
	assert.NotNil(t, aAlerts)
	
	stats = attackWrapper.GetStats()
	assert.NotNil(t, stats)
	
	// Should not panic (no-op)
	attackWrapper.ClearAlerts()
}

func TestUnifiedDetectionEngine_Concurrency(t *testing.T) {
	config := UnifiedConfig{
		EnabledEngines: []string{"snort", "suricata"},
		OutputFormat:   "json",
	}
	ude := NewUnifiedDetectionEngine(config)

	// Test concurrent packet processing
	done := make(chan bool, 10)
	
	for i := 0; i < 10; i++ {
		go func() {
			packet := createTestPacket()
			ude.ProcessPacket(packet)
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	stats := ude.GetStats()
	assert.Equal(t, uint64(10), stats.TotalPackets)
}

func TestUnifiedDetectionEngine_ZeekEventNormalization(t *testing.T) {
	config := UnifiedConfig{}
	ude := NewUnifiedDetectionEngine(config)

	// Test alertable event
	event := ZeekEvent{
		UID:       "test-uid",
		Timestamp: time.Now(),
		Type:      "scan_detected",
		Details: map[string]interface{}{
			"scanner": "192.168.1.100",
			"target":  "192.168.1.0/24",
		},
	}

	alert := ude.normalizeZeekEvent(event)
	require.NotNil(t, alert)
	assert.Equal(t, "zeek", alert.Engine)
	assert.Equal(t, SeverityHigh, alert.Severity)
	assert.Equal(t, "network_event", alert.Type)
	assert.Contains(t, alert.ID, "zeek-test-uid")

	// Test non-alertable event
	event.Type = "random_event"
	alert = ude.normalizeZeekEvent(event)
	assert.Nil(t, alert)
}

func TestUnifiedDetectionEngine_UpdateStats(t *testing.T) {
	config := UnifiedConfig{}
	ude := NewUnifiedDetectionEngine(config)

	alerts := []UnifiedAlert{
		{
			Engine:   "snort",
			Severity: SeverityHigh,
			Type:     "ids_alert",
		},
		{
			Engine:   "suricata",
			Severity: SeverityCritical,
			Type:     "ids_alert",
		},
		{
			Engine:   "yara",
			Severity: SeverityMedium,
			Type:     "malware_detection",
		},
	}

	ude.updateStats(alerts)

	stats := ude.GetStats()
	assert.Equal(t, uint64(1), stats.TotalPackets)
	assert.Equal(t, uint64(3), stats.TotalAlerts)
	assert.Equal(t, uint64(1), stats.AlertsByEngine["snort"])
	assert.Equal(t, uint64(1), stats.AlertsByEngine["suricata"])
	assert.Equal(t, uint64(1), stats.AlertsByEngine["yara"])
	assert.Equal(t, uint64(1), stats.AlertsBySeverity[string(SeverityHigh)])
	assert.Equal(t, uint64(1), stats.AlertsBySeverity[string(SeverityCritical)])
	assert.Equal(t, uint64(1), stats.AlertsBySeverity[string(SeverityMedium)])
	assert.Equal(t, uint64(2), stats.AlertsByType["ids_alert"])
	assert.Equal(t, uint64(1), stats.AlertsByType["malware_detection"])
}

func TestUnifiedConfig_TimeWindow(t *testing.T) {
	config := UnifiedConfig{
		EnabledEngines:   []string{"snort"},
		CorrelationRules: []CorrelationRule{},
		OutputFormat:     "json",
		AlertThreshold:   10,
		TimeWindow:       5 * time.Minute,
	}

	assert.Equal(t, 5*time.Minute, config.TimeWindow)
	assert.Equal(t, 10, config.AlertThreshold)
}

func TestCorrelationCondition(t *testing.T) {
	condition := CorrelationCondition{
		Field:    "source_ip",
		Operator: "equals",
		Value:    "192.168.1.100",
	}

	assert.Equal(t, "source_ip", condition.Field)
	assert.Equal(t, "equals", condition.Operator)
	assert.Equal(t, "192.168.1.100", condition.Value)
}

func TestCorrelationAction(t *testing.T) {
	action := CorrelationAction{
		Type:     "alert",
		Severity: SeverityCritical,
		Message:  "Correlated attack detected",
		Metadata: map[string]interface{}{
			"correlated_count": 5,
		},
	}

	assert.Equal(t, "alert", action.Type)
	assert.Equal(t, SeverityCritical, action.Severity)
	assert.Equal(t, "Correlated attack detected", action.Message)
	assert.Equal(t, 5, action.Metadata["correlated_count"])
}

func TestUnifiedAlert_Metadata(t *testing.T) {
	alert := UnifiedAlert{
		ID:        "test-1",
		Timestamp: time.Now(),
		Engine:    "test",
		Severity:  SeverityHigh,
		Type:      "test_alert",
		Metadata: map[string]interface{}{
			"custom_field": "custom_value",
			"score":        100,
		},
	}

	assert.Equal(t, "custom_value", alert.Metadata["custom_field"])
	assert.Equal(t, 100, alert.Metadata["score"])
}

func TestUnifiedDetectionEngine_ExportFormats(t *testing.T) {
	config := UnifiedConfig{
		EnabledEngines: []string{},
		OutputFormat:   "json",
	}
	ude := NewUnifiedDetectionEngine(config)

	// Add alert with all fields for comprehensive export testing
	alert := UnifiedAlert{
		ID:            "test-comprehensive",
		Timestamp:     time.Now(),
		Engine:        "test",
		Severity:      SeverityHigh,
		Type:          "test_alert",
		Signature:     "TEST-COMPREHENSIVE",
		Message:       "Comprehensive test alert",
		SourceIP:      "10.0.0.1",
		DestIP:        "10.0.0.2",
		SourcePort:    54321,
		DestPort:      443,
		Protocol:      "TCP",
		Correlated:    true,
		CorrelationID: "corr-123",
		Metadata: map[string]interface{}{
			"additional_info": "test",
		},
	}

	ude.mu.Lock()
	ude.alerts = append(ude.alerts, alert)
	ude.mu.Unlock()

	// Test each export format contains expected fields
	formats := []string{"json", "cef", "leef", "syslog"}
	
	for _, format := range formats {
		data, err := ude.ExportAlerts(format)
		require.NoError(t, err)
		assert.NotEmpty(t, data)
		
		// Verify key information is present
		output := string(data)
		if format == "json" {
			assert.Contains(t, output, "test-comprehensive")
			assert.Contains(t, output, "TEST-COMPREHENSIVE")
			assert.Contains(t, output, "10.0.0.1")
			assert.Contains(t, output, "10.0.0.2")
		}
	}
}

func TestUnifiedDetectionEngine_EmptyProcessing(t *testing.T) {
	config := UnifiedConfig{
		EnabledEngines: []string{},
		OutputFormat:   "json",
	}
	ude := NewUnifiedDetectionEngine(config)

	// Process packet with no engines enabled
	packet := createTestPacket()
	alerts := ude.ProcessPacket(packet)
	assert.Empty(t, alerts)

	// Export empty alerts
	data, err := ude.ExportAlerts("json")
	require.NoError(t, err)
	assert.Equal(t, "[]", strings.TrimSpace(string(data)))
}