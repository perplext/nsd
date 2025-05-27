package security

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
)

// UnifiedDetectionEngine manages all detection engines in a single framework
type UnifiedDetectionEngine struct {
	snortEngine    *SnortEngine
	suricataEngine *SuricataEngine
	zeekEngine     *ZeekEngine
	yaraEngine     *YARAEngine
	sigmaEngine    *SigmaEngine
	networkAttackDetector *NetworkAttackDetector
	
	engines        map[string]DetectionEngine
	config         UnifiedConfig
	alerts         []UnifiedAlert
	stats          UnifiedStats
	correlator     *AlertCorrelator
	mu             sync.RWMutex
}

// DetectionEngine interface for all engines
type DetectionEngine interface {
	ProcessPacket(packet gopacket.Packet) interface{}
	GetStats() interface{}
	ClearAlerts()
}

// UnifiedConfig holds configuration for the unified engine
type UnifiedConfig struct {
	EnabledEngines   []string
	CorrelationRules []CorrelationRule
	OutputFormat     string // "json", "cef", "leef", "syslog"
	AlertThreshold   int
	TimeWindow       time.Duration
}

// UnifiedAlert represents a normalized alert from any engine
type UnifiedAlert struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	Engine       string                 `json:"engine"`
	Severity     AlertSeverity          `json:"severity"`
	Type         string                 `json:"type"`
	Signature    string                 `json:"signature"`
	Message      string                 `json:"message"`
	SourceIP     string                 `json:"source_ip"`
	DestIP       string                 `json:"dest_ip"`
	SourcePort   int                    `json:"source_port,omitempty"`
	DestPort     int                    `json:"dest_port,omitempty"`
	Protocol     string                 `json:"protocol,omitempty"`
	RawData      interface{}            `json:"raw_data,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	Correlated   bool                   `json:"correlated"`
	CorrelationID string                `json:"correlation_id,omitempty"`
}

// AlertSeverity levels
type AlertSeverity string

const (
	SeverityLow      AlertSeverity = "low"
	SeverityMedium   AlertSeverity = "medium"
	SeverityHigh     AlertSeverity = "high"
	SeverityCritical AlertSeverity = "critical"
)

// UnifiedStats tracks statistics across all engines
type UnifiedStats struct {
	TotalPackets     uint64            `json:"total_packets"`
	TotalAlerts      uint64            `json:"total_alerts"`
	AlertsByEngine   map[string]uint64 `json:"alerts_by_engine"`
	AlertsBySeverity map[string]uint64 `json:"alerts_by_severity"`
	AlertsByType     map[string]uint64 `json:"alerts_by_type"`
	LastUpdate       time.Time         `json:"last_update"`
}

// CorrelationRule defines rules for correlating alerts
type CorrelationRule struct {
	ID          string
	Name        string
	Description string
	Conditions  []CorrelationCondition
	TimeWindow  time.Duration
	Action      CorrelationAction
}

// CorrelationCondition defines conditions for correlation
type CorrelationCondition struct {
	Field    string
	Operator string // "equals", "contains", "regex", "in"
	Value    interface{}
}

// CorrelationAction defines what to do when correlation matches
type CorrelationAction struct {
	Type        string // "alert", "suppress", "enhance"
	Severity    AlertSeverity
	Message     string
	Metadata    map[string]interface{}
}

// AlertCorrelator handles alert correlation logic
type AlertCorrelator struct {
	rules       []CorrelationRule
	alertBuffer map[string][]UnifiedAlert
	mu          sync.RWMutex
}

// NewUnifiedDetectionEngine creates a new unified detection engine
func NewUnifiedDetectionEngine(config UnifiedConfig) *UnifiedDetectionEngine {
	ude := &UnifiedDetectionEngine{
		config:         config,
		engines:        make(map[string]DetectionEngine),
		alerts:         make([]UnifiedAlert, 0),
		stats:          UnifiedStats{
			AlertsByEngine:   make(map[string]uint64),
			AlertsBySeverity: make(map[string]uint64),
			AlertsByType:     make(map[string]uint64),
			LastUpdate:       time.Now(),
		},
		correlator:     NewAlertCorrelator(config.CorrelationRules),
	}

	// Initialize engines based on config
	for _, engineName := range config.EnabledEngines {
		switch engineName {
		case "snort":
			ude.snortEngine = NewSnortEngine()
			ude.engines["snort"] = &SnortEngineWrapper{engine: ude.snortEngine}
		case "suricata":
			ude.suricataEngine = NewSuricataEngine(false)
			ude.engines["suricata"] = &SuricataEngineWrapper{engine: ude.suricataEngine}
		case "zeek":
			ude.zeekEngine = NewZeekEngine()
			ude.engines["zeek"] = &ZeekEngineWrapper{engine: ude.zeekEngine}
		case "yara":
			ude.yaraEngine = NewYARAEngine()
			ude.engines["yara"] = &YARAEngineWrapper{engine: ude.yaraEngine}
		case "sigma":
			ude.sigmaEngine = NewSigmaEngine()
			ude.engines["sigma"] = &SigmaEngineWrapper{engine: ude.sigmaEngine}
		case "network_attacks":
			ude.networkAttackDetector = NewNetworkAttackDetector()
			ude.engines["network_attacks"] = &NetworkAttackWrapper{detector: ude.networkAttackDetector}
		}
	}

	return ude
}

// Engine wrappers to implement DetectionEngine interface
type SnortEngineWrapper struct {
	engine *SnortEngine
}

func (w *SnortEngineWrapper) ProcessPacket(packet gopacket.Packet) interface{} {
	return w.engine.ProcessPacket(packet)
}

func (w *SnortEngineWrapper) GetStats() interface{} {
	return w.engine.GetStats()
}

func (w *SnortEngineWrapper) ClearAlerts() {
	w.engine.ClearAlerts()
}

type SuricataEngineWrapper struct {
	engine *SuricataEngine
}

func (w *SuricataEngineWrapper) ProcessPacket(packet gopacket.Packet) interface{} {
	return w.engine.ProcessPacket(packet)
}

func (w *SuricataEngineWrapper) GetStats() interface{} {
	return w.engine.GetStats()
}

func (w *SuricataEngineWrapper) ClearAlerts() {
	w.engine.ClearAlerts()
}

type ZeekEngineWrapper struct {
	engine *ZeekEngine
}

func (w *ZeekEngineWrapper) ProcessPacket(packet gopacket.Packet) interface{} {
	return w.engine.ProcessPacket(packet)
}

func (w *ZeekEngineWrapper) GetStats() interface{} {
	return w.engine.GetStats()
}

func (w *ZeekEngineWrapper) ClearAlerts() {
	w.engine.ClearAlerts()
}

type YARAEngineWrapper struct {
	engine *YARAEngine
}

func (w *YARAEngineWrapper) ProcessPacket(packet gopacket.Packet) interface{} {
	return w.engine.ProcessPacket(packet)
}

func (w *YARAEngineWrapper) GetStats() interface{} {
	return w.engine.GetStats()
}

func (w *YARAEngineWrapper) ClearAlerts() {
	w.engine.ClearAlerts()
}

type SigmaEngineWrapper struct {
	engine *SigmaEngine
}

func (w *SigmaEngineWrapper) ProcessPacket(packet gopacket.Packet) interface{} {
	return w.engine.ProcessPacket(packet)
}

func (w *SigmaEngineWrapper) GetStats() interface{} {
	return w.engine.GetStats()
}

func (w *SigmaEngineWrapper) ClearAlerts() {
	w.engine.ClearAlerts()
}

type NetworkAttackWrapper struct {
	detector *NetworkAttackDetector
}

func (w *NetworkAttackWrapper) ProcessPacket(packet gopacket.Packet) interface{} {
	return w.detector.ProcessPacket(packet)
}

func (w *NetworkAttackWrapper) GetStats() interface{} {
	return w.detector.GetStats()
}

func (w *NetworkAttackWrapper) ClearAlerts() {
	// NetworkAttackDetector doesn't have ClearAlerts, so we'll make it a no-op
}

// ProcessPacket processes a packet through all enabled engines
func (ude *UnifiedDetectionEngine) ProcessPacket(packet gopacket.Packet) []UnifiedAlert {
	ude.mu.Lock()
	defer ude.mu.Unlock()

	var alerts []UnifiedAlert
	
	// Process packet through each enabled engine
	for engineName, _ := range ude.engines {
		switch engineName {
		case "snort":
			if snortAlerts := ude.snortEngine.ProcessPacket(packet); len(snortAlerts) > 0 {
				for _, alert := range snortAlerts {
					unified := ude.normalizeSnortAlert(alert)
					alerts = append(alerts, unified)
				}
			}
		case "suricata":
			if suricataAlerts := ude.suricataEngine.ProcessPacket(packet); len(suricataAlerts) > 0 {
				for _, alert := range suricataAlerts {
					unified := ude.normalizeSuricataAlert(alert)
					alerts = append(alerts, unified)
				}
			}
		case "zeek":
			if zeekEvents := ude.zeekEngine.ProcessPacket(packet); len(zeekEvents) > 0 {
				for _, event := range zeekEvents {
					if unified := ude.normalizeZeekEvent(event); unified != nil {
						alerts = append(alerts, *unified)
					}
				}
			}
		case "yara":
			if yaraMatches := ude.yaraEngine.ProcessPacket(packet); len(yaraMatches) > 0 {
				for _, match := range yaraMatches {
					unified := ude.normalizeYARAMatch(match)
					alerts = append(alerts, unified)
				}
			}
		case "sigma":
			if sigmaAlerts := ude.sigmaEngine.ProcessPacket(packet); len(sigmaAlerts) > 0 {
				for _, alert := range sigmaAlerts {
					unified := ude.normalizeSigmaAlert(alert)
					alerts = append(alerts, unified)
				}
			}
		case "network_attacks":
			if attacks := ude.networkAttackDetector.ProcessPacket(packet); len(attacks) > 0 {
				for _, attack := range attacks {
					unified := ude.normalizeNetworkAttack(attack)
					alerts = append(alerts, unified)
				}
			}
		}
	}
	
	// Correlate alerts
	correlated := ude.correlator.CorrelateAlerts(alerts)
	
	// Update statistics
	ude.updateStats(correlated)
	
	// Store alerts
	ude.alerts = append(ude.alerts, correlated...)
	
	return correlated
}

// Normalization methods
func (ude *UnifiedDetectionEngine) normalizeSnortAlert(alert SnortAlert) UnifiedAlert {
	return UnifiedAlert{
		ID:          fmt.Sprintf("snort-%s", alert.Timestamp.Format("20060102150405")),
		Timestamp:   alert.Timestamp,
		Engine:      "snort",
		Severity:    ude.mapSnortPriority(alert.Priority),
		Type:        "ids_alert",
		Signature:   fmt.Sprintf("SID:%d", alert.SID),
		Message:     alert.Message,
		SourceIP:    alert.SrcIP,
		DestIP:      alert.DstIP,
		SourcePort:  alert.SrcPort,
		DestPort:    alert.DstPort,
		Protocol:    alert.Protocol,
		RawData:     alert,
		Metadata: map[string]interface{}{
			"rule_id": alert.RuleID,
			"classtype": alert.Classtype,
		},
	}
}

func (ude *UnifiedDetectionEngine) normalizeSuricataAlert(alert SuricataAlert) UnifiedAlert {
	return UnifiedAlert{
		ID:          fmt.Sprintf("suricata-%s", alert.Timestamp),
		Timestamp:   time.Now(), // Parse from alert.Timestamp if needed
		Engine:      "suricata",
		Severity:    ude.mapSuricataSeverity(alert.Alert.Severity),
		Type:        "ids_alert",
		Signature:   alert.Alert.Signature,
		Message:     alert.Alert.Signature,
		SourceIP:    alert.SrcIP,
		DestIP:      alert.DstIP,
		SourcePort:  alert.SrcPort,
		DestPort:    alert.DstPort,
		Protocol:    alert.Protocol,
		RawData:     alert,
		Metadata: map[string]interface{}{
			"signature_id": alert.Alert.SignatureID,
			"category":     alert.Alert.Category,
		},
	}
}

func (ude *UnifiedDetectionEngine) normalizeZeekEvent(event ZeekEvent) *UnifiedAlert {
	// Only convert certain event types to alerts
	if !ude.isAlertableZeekEvent(event.Type) {
		return nil
	}
	
	return &UnifiedAlert{
		ID:          fmt.Sprintf("zeek-%s-%s", event.UID, event.Timestamp.Format("20060102150405")),
		Timestamp:   event.Timestamp,
		Engine:      "zeek",
		Severity:    ude.mapZeekEventSeverity(event.Type),
		Type:        "network_event",
		Signature:   event.Type,
		Message:     fmt.Sprintf("Zeek event: %s", event.Type),
		RawData:     event,
		Metadata:    event.Details,
	}
}

func (ude *UnifiedDetectionEngine) normalizeYARAMatch(match YARAMatch) UnifiedAlert {
	return UnifiedAlert{
		ID:          fmt.Sprintf("yara-%s-%s", match.RuleName, match.Timestamp.Format("20060102150405")),
		Timestamp:   match.Timestamp,
		Engine:      "yara",
		Severity:    ude.mapYARATags(match.Tags),
		Type:        "malware_detection",
		Signature:   match.RuleName,
		Message:     fmt.Sprintf("YARA rule matched: %s", match.RuleName),
		SourceIP:    match.PacketInfo.SrcIP,
		DestIP:      match.PacketInfo.DstIP,
		Protocol:    match.PacketInfo.Protocol,
		RawData:     match,
		Metadata:    convertStringMapToInterface(match.Meta),
	}
}

func (ude *UnifiedDetectionEngine) normalizeSigmaAlert(alert SigmaAlert) UnifiedAlert {
	return UnifiedAlert{
		ID:          fmt.Sprintf("sigma-%s", alert.RuleID),
		Timestamp:   alert.Timestamp,
		Engine:      "sigma",
		Severity:    AlertSeverity(strings.ToLower(alert.Level)),
		Type:        "security_event",
		Signature:   alert.RuleTitle,
		Message:     alert.Message,
		RawData:     alert,
		Metadata:    alert.MatchedFields,
	}
}

func (ude *UnifiedDetectionEngine) normalizeNetworkAttack(attack AttackAlert) UnifiedAlert {
	return UnifiedAlert{
		ID:          fmt.Sprintf("netattack-%s-%s", attack.Type, attack.Timestamp.Format("20060102150405")),
		Timestamp:   attack.Timestamp,
		Engine:      "network_attacks",
		Severity:    AlertSeverity(strings.ToLower(attack.Severity)),
		Type:        "network_attack",
		Signature:   attack.Type,
		Message:     attack.Description,
		SourceIP:    attack.SourceIP,
		DestIP:      attack.DestIP,
		RawData:     attack,
		Metadata:    attack.Details,
	}
}

// Helper methods
func (ude *UnifiedDetectionEngine) mapSnortPriority(priority int) AlertSeverity {
	switch priority {
	case 1:
		return SeverityCritical
	case 2:
		return SeverityHigh
	case 3:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

func (ude *UnifiedDetectionEngine) mapSuricataSeverity(severity int) AlertSeverity {
	switch severity {
	case 1:
		return SeverityCritical
	case 2:
		return SeverityHigh
	case 3:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

func (ude *UnifiedDetectionEngine) mapZeekEventSeverity(eventType string) AlertSeverity {
	// Map certain Zeek events to severity levels
	criticalEvents := []string{"exploit", "malware", "backdoor"}
	highEvents := []string{"scan", "bruteforce", "dos"}
	
	for _, event := range criticalEvents {
		if strings.Contains(strings.ToLower(eventType), event) {
			return SeverityCritical
		}
	}
	
	for _, event := range highEvents {
		if strings.Contains(strings.ToLower(eventType), event) {
			return SeverityHigh
		}
	}
	
	return SeverityMedium
}

func (ude *UnifiedDetectionEngine) mapYARATags(tags []string) AlertSeverity {
	for _, tag := range tags {
		switch strings.ToLower(tag) {
		case "critical", "apt", "ransomware":
			return SeverityCritical
		case "malware", "trojan", "backdoor":
			return SeverityHigh
		case "suspicious", "pup":
			return SeverityMedium
		}
	}
	return SeverityLow
}

func (ude *UnifiedDetectionEngine) isAlertableZeekEvent(eventType string) bool {
	alertableEvents := []string{
		"connection_established",
		"dns_query",
		"http_request",
		"ssl_certificate",
		"file_transfer",
		"scan_detected",
		"exploit_attempt",
	}
	
	for _, event := range alertableEvents {
		if strings.Contains(eventType, event) {
			return true
		}
	}
	return false
}

func (ude *UnifiedDetectionEngine) updateStats(alerts []UnifiedAlert) {
	ude.stats.TotalPackets++
	ude.stats.TotalAlerts += uint64(len(alerts))
	ude.stats.LastUpdate = time.Now()
	
	for _, alert := range alerts {
		ude.stats.AlertsByEngine[alert.Engine]++
		ude.stats.AlertsBySeverity[string(alert.Severity)]++
		ude.stats.AlertsByType[alert.Type]++
	}
}

// GetAlerts returns all alerts
func (ude *UnifiedDetectionEngine) GetAlerts() []UnifiedAlert {
	ude.mu.RLock()
	defer ude.mu.RUnlock()
	
	return append([]UnifiedAlert{}, ude.alerts...)
}

// GetStats returns unified statistics
func (ude *UnifiedDetectionEngine) GetStats() UnifiedStats {
	ude.mu.RLock()
	defer ude.mu.RUnlock()
	
	return ude.stats
}

// ClearAlerts clears all alerts
func (ude *UnifiedDetectionEngine) ClearAlerts() {
	ude.mu.Lock()
	defer ude.mu.Unlock()
	
	ude.alerts = make([]UnifiedAlert, 0)
	
	// Clear alerts in all engines
	for _, engine := range ude.engines {
		engine.ClearAlerts()
	}
}

// ExportAlerts exports alerts in specified format
func (ude *UnifiedDetectionEngine) ExportAlerts(format string) ([]byte, error) {
	ude.mu.RLock()
	defer ude.mu.RUnlock()
	
	switch format {
	case "json":
		return json.MarshalIndent(ude.alerts, "", "  ")
	case "cef":
		return ude.exportCEF()
	case "leef":
		return ude.exportLEEF()
	case "syslog":
		return ude.exportSyslog()
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

func (ude *UnifiedDetectionEngine) exportCEF() ([]byte, error) {
	var output strings.Builder
	
	for _, alert := range ude.alerts {
		cef := fmt.Sprintf("CEF:0|NetMon|UnifiedDetection|1.0|%s|%s|%d|src=%s dst=%s spt=%d dpt=%d proto=%s\n",
			alert.Signature,
			alert.Message,
			ude.severityToInt(alert.Severity),
			alert.SourceIP,
			alert.DestIP,
			alert.SourcePort,
			alert.DestPort,
			alert.Protocol,
		)
		output.WriteString(cef)
	}
	
	return []byte(output.String()), nil
}

func (ude *UnifiedDetectionEngine) exportLEEF() ([]byte, error) {
	var output strings.Builder
	
	for _, alert := range ude.alerts {
		leef := fmt.Sprintf("LEEF:1.0|NetMon|UnifiedDetection|1.0|%s|src=%s|dst=%s|sev=%d\n",
			alert.Signature,
			alert.SourceIP,
			alert.DestIP,
			ude.severityToInt(alert.Severity),
		)
		output.WriteString(leef)
	}
	
	return []byte(output.String()), nil
}

func (ude *UnifiedDetectionEngine) exportSyslog() ([]byte, error) {
	var output strings.Builder
	
	for _, alert := range ude.alerts {
		syslog := fmt.Sprintf("<%d>%s netmon[unified]: %s - %s (src=%s dst=%s)\n",
			16 + ude.severityToInt(alert.Severity), // Facility 2 (mail) + severity
			alert.Timestamp.Format(time.RFC3339),
			alert.Signature,
			alert.Message,
			alert.SourceIP,
			alert.DestIP,
		)
		output.WriteString(syslog)
	}
	
	return []byte(output.String()), nil
}

func (ude *UnifiedDetectionEngine) severityToInt(severity AlertSeverity) int {
	switch severity {
	case SeverityCritical:
		return 1
	case SeverityHigh:
		return 2
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 4
	default:
		return 5
	}
}

// NewAlertCorrelator creates a new alert correlator
func NewAlertCorrelator(rules []CorrelationRule) *AlertCorrelator {
	return &AlertCorrelator{
		rules:       rules,
		alertBuffer: make(map[string][]UnifiedAlert),
	}
}

// CorrelateAlerts correlates alerts based on rules
func (ac *AlertCorrelator) CorrelateAlerts(alerts []UnifiedAlert) []UnifiedAlert {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	
	// For now, just return alerts as-is
	// TODO: Implement correlation logic
	return alerts
}

// Helper function to convert map[string]string to map[string]interface{}
func convertStringMapToInterface(m map[string]string) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range m {
		result[k] = v
	}
	return result
}