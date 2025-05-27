package security

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"gopkg.in/yaml.v3"
)

// SigmaEngine implements Sigma rule processing for generic SIEM detection
type SigmaEngine struct {
	rules    []SigmaRule
	alerts   []SigmaAlert
	stats    SigmaStats
	fieldMap map[string]string // Maps Sigma fields to packet fields
}

type SigmaRule struct {
	Title         string                            `yaml:"title"`
	ID            string                            `yaml:"id"`
	Status        string                            `yaml:"status"`
	Description   string                            `yaml:"description"`
	Author        string                            `yaml:"author"`
	Date          string                            `yaml:"date"`
	Modified      string                            `yaml:"modified"`
	References    []string                          `yaml:"references"`
	Tags          []string                          `yaml:"tags"`
	LogSource     SigmaLogSource                    `yaml:"logsource"`
	Detection     SigmaDetection                    `yaml:"detection"`
	Fields        []string                          `yaml:"fields"`
	FalsePositives []string                         `yaml:"falsepositives"`
	Level         string                            `yaml:"level"`
	Compiled      *CompiledSigmaRule                `yaml:"-"`
}

type SigmaLogSource struct {
	Category   string `yaml:"category"`
	Product    string `yaml:"product"`
	Service    string `yaml:"service"`
	Definition string `yaml:"definition"`
}

type SigmaDetection struct {
	Selection  map[string]interface{} `yaml:"selection"`
	Condition  string                 `yaml:"condition"`
	Timeframe  string                 `yaml:"timeframe"`
	Filters    []map[string]interface{} `yaml:"filter"`
}

type CompiledSigmaRule struct {
	Matchers  []FieldMatcher
	Condition *ConditionEvaluator
	Timeframe time.Duration
}

type FieldMatcher struct {
	Field     string
	Operator  string // "equals", "contains", "startswith", "endswith", "regex", "gt", "lt", "gte", "lte"
	Value     interface{}
	Modifiers []string // "all", "ignorecase"
}

type ConditionEvaluator struct {
	Expression string
	Type       string // "and", "or", "not", "near", "sequence"
	Operands   []*ConditionEvaluator
}

type SigmaAlert struct {
	Timestamp  time.Time              `json:"timestamp"`
	RuleID     string                 `json:"rule_id"`
	RuleTitle  string                 `json:"rule_title"`
	Level      string                 `json:"level"`
	Tags       []string               `json:"tags"`
	Message    string                 `json:"message"`
	MatchedFields map[string]interface{} `json:"matched_fields"`
	PacketInfo map[string]interface{} `json:"packet_info"`
	References []string               `json:"references"`
}

type SigmaStats struct {
	TotalPackets   uint64
	TotalAlerts    uint64
	AlertsByRule   map[string]uint64
	AlertsByLevel  map[string]uint64
	AlertsByTag    map[string]uint64
}

func NewSigmaEngine() *SigmaEngine {
	engine := &SigmaEngine{
		rules:  make([]SigmaRule, 0),
		alerts: make([]SigmaAlert, 0),
		stats: SigmaStats{
			AlertsByRule:  make(map[string]uint64),
			AlertsByLevel: make(map[string]uint64),
			AlertsByTag:   make(map[string]uint64),
		},
		fieldMap: make(map[string]string),
	}
	
	engine.initFieldMapping()
	engine.loadDefaultRules()
	
	return engine
}

func (se *SigmaEngine) initFieldMapping() {
	// Map Sigma field names to packet fields
	se.fieldMap = map[string]string{
		// Network fields
		"source.ip":        "src_ip",
		"destination.ip":   "dst_ip",
		"source.port":      "src_port",
		"destination.port": "dst_port",
		"network.protocol": "protocol",
		"network.transport": "transport",
		
		// DNS fields
		"dns.question.name": "dns_query",
		"dns.question.type": "dns_query_type",
		"dns.response_code": "dns_response_code",
		
		// HTTP fields
		"http.request.method": "http_method",
		"http.request.url": "http_url",
		"http.request.body.content": "http_body",
		"http.response.status_code": "http_status",
		"user_agent": "http_user_agent",
		
		// Process fields (for endpoint detection)
		"process.command_line": "command_line",
		"process.name": "process_name",
		"process.parent.name": "parent_process",
		
		// File fields
		"file.path": "file_path",
		"file.name": "file_name",
		"file.hash.md5": "file_md5",
		"file.hash.sha256": "file_sha256",
		
		// Event fields
		"event.category": "event_category",
		"event.type": "event_type",
		"event.action": "event_action",
	}
}

func (se *SigmaEngine) loadDefaultRules() {
	// Load default Sigma rules for network detection
	defaultRules := []SigmaRule{
		{
			Title:       "Suspicious Network Scanning Activity",
			ID:          "sigma-net-001",
			Status:      "stable",
			Description: "Detects potential network scanning based on connection patterns",
			Author:      "NetMon Security",
			Level:       "medium",
			Tags:        []string{"attack.discovery", "attack.t1046"},
			LogSource: SigmaLogSource{
				Category: "network",
				Product:  "netmon",
			},
			Detection: SigmaDetection{
				Selection: map[string]interface{}{
					"destination.port|count|gte": 20,
					"source.ip|grouped": true,
					"timeframe": "60s",
				},
				Condition: "selection",
			},
		},
		{
			Title:       "Potential SQL Injection Attack",
			ID:          "sigma-web-001", 
			Status:      "stable",
			Description: "Detects potential SQL injection attempts in web traffic",
			Author:      "NetMon Security",
			Level:       "high",
			Tags:        []string{"attack.initial_access", "attack.t1190"},
			LogSource: SigmaLogSource{
				Category: "webserver",
				Product:  "netmon",
			},
			Detection: SigmaDetection{
				Selection: map[string]interface{}{
					"http.request.url|contains|all": []string{"UNION", "SELECT"},
					"http.request.method": "GET",
				},
				Condition: "selection",
			},
			FalsePositives: []string{"Legitimate database administration tools"},
		},
		{
			Title:       "DNS Tunneling Detection",
			ID:          "sigma-dns-001",
			Status:      "experimental",
			Description: "Detects potential DNS tunneling based on query characteristics",
			Author:      "NetMon Security",
			Level:       "medium",
			Tags:        []string{"attack.exfiltration", "attack.t1048"},
			LogSource: SigmaLogSource{
				Category: "dns",
				Product:  "netmon",
			},
			Detection: SigmaDetection{
				Selection: map[string]interface{}{
					"dns.question.name|regex": "[a-zA-Z0-9]{50,}\\.",
					"dns.question.type": "TXT",
				},
				Condition: "selection",
			},
		},
		{
			Title:       "Suspicious Outbound SMTP Traffic",
			ID:          "sigma-email-001",
			Status:      "stable",
			Description: "Detects unusual SMTP traffic that may indicate spam or malware",
			Author:      "NetMon Security",
			Level:       "medium",
			Tags:        []string{"attack.collection", "attack.t1114"},
			LogSource: SigmaLogSource{
				Category: "network",
				Product:  "netmon",
			},
			Detection: SigmaDetection{
				Selection: map[string]interface{}{
					"destination.port": 25,
					"source.ip|private": false,
					"destination.ip|count|gt": 5,
				},
				Condition: "selection",
				Timeframe: "5m",
			},
		},
		{
			Title:       "Potential Brute Force Attack",
			ID:          "sigma-auth-001",
			Status:      "stable",
			Description: "Detects multiple failed authentication attempts",
			Author:      "NetMon Security",
			Level:       "high",
			Tags:        []string{"attack.credential_access", "attack.t1110"},
			LogSource: SigmaLogSource{
				Category: "authentication",
				Product:  "netmon",
			},
			Detection: SigmaDetection{
				Selection: map[string]interface{}{
					"event.action": "logon_failed",
					"source.ip|count|gte": 5,
				},
				Condition: "selection",
				Timeframe: "5m",
			},
		},
		{
			Title:       "Data Exfiltration via HTTP POST",
			ID:          "sigma-exfil-001",
			Status:      "experimental",
			Description: "Detects potential data exfiltration using HTTP POST requests",
			Author:      "NetMon Security",
			Level:       "high",
			Tags:        []string{"attack.exfiltration", "attack.t1041"},
			LogSource: SigmaLogSource{
				Category: "webserver",
				Product:  "netmon",
			},
			Detection: SigmaDetection{
				Selection: map[string]interface{}{
					"http.request.method": "POST",
					"http.request.body.bytes|gt": 1048576, // 1MB
					"destination.ip|public": true,
				},
				Condition: "selection",
			},
		},
		{
			Title:       "Suspicious PowerShell Download",
			ID:          "sigma-ps-001",
			Status:      "stable",
			Description: "Detects PowerShell downloading content from the internet",
			Author:      "NetMon Security",
			Level:       "high",
			Tags:        []string{"attack.execution", "attack.t1059.001"},
			LogSource: SigmaLogSource{
				Category: "network",
				Product:  "netmon",
			},
			Detection: SigmaDetection{
				Selection: map[string]interface{}{
					"user_agent|contains": "PowerShell",
					"http.request.method": []string{"GET", "POST"},
				},
				Condition: "selection",
			},
		},
		{
			Title:       "Cryptocurrency Mining Pool Connection",
			ID:          "sigma-crypto-001",
			Status:      "stable",
			Description: "Detects connections to known cryptocurrency mining pools",
			Author:      "NetMon Security",
			Level:       "high",
			Tags:        []string{"attack.impact", "attack.t1496"},
			LogSource: SigmaLogSource{
				Category: "network",
				Product:  "netmon",
			},
			Detection: SigmaDetection{
				Selection: map[string]interface{}{
					"destination.port": []int{3333, 4444, 8333, 8888, 9999},
					"network.protocol": "tcp",
					"network.bytes|gt": 1000,
				},
				Condition: "selection",
			},
		},
		{
			Title:       "IRC Botnet Communication",
			ID:          "sigma-irc-001",
			Status:      "experimental",
			Description: "Detects potential IRC botnet command and control communication",
			Author:      "NetMon Security",
			Level:       "high",
			Tags:        []string{"attack.command_and_control", "attack.t1071"},
			LogSource: SigmaLogSource{
				Category: "network",
				Product:  "netmon",
			},
			Detection: SigmaDetection{
				Selection: map[string]interface{}{
					"destination.port": []int{6666, 6667, 6668, 6669, 7000},
					"network.protocol": "tcp",
					"payload|contains|any": []string{"PRIVMSG", "JOIN", "NICK"},
				},
				Condition: "selection",
			},
		},
		{
			Title:       "Log4j Exploitation Attempt",
			ID:          "sigma-log4j-001",
			Status:      "stable",
			Description: "Detects Log4j vulnerability exploitation attempts (CVE-2021-44228)",
			Author:      "NetMon Security",
			Level:       "critical",
			Tags:        []string{"attack.initial_access", "cve.2021.44228"},
			References:  []string{"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228"},
			LogSource: SigmaLogSource{
				Category: "webserver",
				Product:  "netmon",
			},
			Detection: SigmaDetection{
				Selection: map[string]interface{}{
					"payload|contains": "${jndi:",
					"payload|contains|any": []string{"ldap://", "ldaps://", "rmi://", "dns://"},
				},
				Condition: "selection",
			},
		},
	}
	
	// Compile rules
	for i := range defaultRules {
		se.compileRule(&defaultRules[i])
		se.rules = append(se.rules, defaultRules[i])
	}
}

func (se *SigmaEngine) compileRule(rule *SigmaRule) error {
	compiled := &CompiledSigmaRule{
		Matchers: make([]FieldMatcher, 0),
	}
	
	// Parse selection criteria
	for field, value := range rule.Detection.Selection {
		matcher := se.parseFieldMatcher(field, value)
		if matcher != nil {
			compiled.Matchers = append(compiled.Matchers, *matcher)
		}
	}
	
	// Parse timeframe
	if rule.Detection.Timeframe != "" {
		duration, err := se.parseTimeframe(rule.Detection.Timeframe)
		if err == nil {
			compiled.Timeframe = duration
		}
	}
	
	// Parse condition
	compiled.Condition = se.parseCondition(rule.Detection.Condition)
	
	rule.Compiled = compiled
	return nil
}

func (se *SigmaEngine) parseFieldMatcher(field string, value interface{}) *FieldMatcher {
	matcher := &FieldMatcher{
		Value: value,
	}
	
	// Parse field with modifiers
	parts := strings.Split(field, "|")
	matcher.Field = se.mapField(parts[0])
	
	if len(parts) > 1 {
		for i := 1; i < len(parts); i++ {
			modifier := strings.ToLower(parts[i])
			switch modifier {
			case "contains", "startswith", "endswith", "regex", "equals":
				matcher.Operator = modifier
			case "gt", "lt", "gte", "lte":
				matcher.Operator = modifier
			case "count":
				matcher.Operator = "count"
			case "all", "any", "ignorecase":
				matcher.Modifiers = append(matcher.Modifiers, modifier)
			}
		}
	}
	
	if matcher.Operator == "" {
		matcher.Operator = "equals"
	}
	
	return matcher
}

func (se *SigmaEngine) mapField(sigmaField string) string {
	if mapped, ok := se.fieldMap[sigmaField]; ok {
		return mapped
	}
	return sigmaField
}

func (se *SigmaEngine) parseTimeframe(timeframe string) (time.Duration, error) {
	// Parse Sigma timeframe format (e.g., "5m", "1h", "60s")
	return time.ParseDuration(timeframe)
}

func (se *SigmaEngine) parseCondition(condition string) *ConditionEvaluator {
	// Simple condition parser
	condition = strings.TrimSpace(condition)
	
	if condition == "selection" {
		return &ConditionEvaluator{
			Expression: "selection",
			Type:       "selection",
		}
	}
	
	// Handle more complex conditions (simplified)
	if strings.Contains(condition, " and ") {
		return &ConditionEvaluator{
			Expression: condition,
			Type:       "and",
		}
	}
	
	if strings.Contains(condition, " or ") {
		return &ConditionEvaluator{
			Expression: condition,
			Type:       "or",
		}
	}
	
	return &ConditionEvaluator{
		Expression: condition,
		Type:       "simple",
	}
}

func (se *SigmaEngine) ProcessPacket(packet gopacket.Packet) []SigmaAlert {
	se.stats.TotalPackets++
	
	// Extract packet data into fields
	packetData := se.extractPacketData(packet)
	
	var alerts []SigmaAlert
	
	// Check each rule
	for _, rule := range se.rules {
		if se.matchRule(rule, packetData) {
			alert := se.createAlert(rule, packetData)
			alerts = append(alerts, alert)
			se.alerts = append(se.alerts, alert)
			
			se.stats.TotalAlerts++
			se.stats.AlertsByRule[rule.ID]++
			se.stats.AlertsByLevel[rule.Level]++
			
			for _, tag := range rule.Tags {
				se.stats.AlertsByTag[tag]++
			}
		}
	}
	
	return alerts
}

func (se *SigmaEngine) extractPacketData(packet gopacket.Packet) map[string]interface{} {
	data := make(map[string]interface{})
	
	// Network layer
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		data["src_ip"] = netLayer.NetworkFlow().Src().String()
		data["dst_ip"] = netLayer.NetworkFlow().Dst().String()
		
		// Check if IPs are private/public
		srcIP := netLayer.NetworkFlow().Src().String()
		dstIP := netLayer.NetworkFlow().Dst().String()
		data["src_ip_private"] = se.isPrivateIP(srcIP)
		data["dst_ip_private"] = se.isPrivateIP(dstIP)
		data["src_ip_public"] = !se.isPrivateIP(srcIP)
		data["dst_ip_public"] = !se.isPrivateIP(dstIP)
	}
	
	// Transport layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		data["src_port"] = int(tcp.SrcPort)
		data["dst_port"] = int(tcp.DstPort)
		data["protocol"] = "tcp"
		data["transport"] = "tcp"
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		data["src_port"] = int(udp.SrcPort)
		data["dst_port"] = int(udp.DstPort)
		data["protocol"] = "udp"
		data["transport"] = "udp"
	}
	
	// Application layer
	if app := packet.ApplicationLayer(); app != nil {
		payload := app.Payload()
		data["payload"] = string(payload)
		data["payload_bytes"] = len(payload)
		
		// Try to parse HTTP
		if httpData := se.parseHTTP(payload); httpData != nil {
			for k, v := range httpData {
				data[k] = v
			}
		}
		
		// DNS layer
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dns := dnsLayer.(*layers.DNS)
			if len(dns.Questions) > 0 {
				data["dns_query"] = string(dns.Questions[0].Name)
				data["dns_query_type"] = dns.Questions[0].Type.String()
			}
		}
	}
	
	data["timestamp"] = time.Now()
	data["packet_size"] = len(packet.Data())
	
	return data
}

func (se *SigmaEngine) parseHTTP(payload []byte) map[string]interface{} {
	payloadStr := string(payload)
	if !strings.Contains(payloadStr, "HTTP/") {
		return nil
	}
	
	httpData := make(map[string]interface{})
	lines := strings.Split(payloadStr, "\r\n")
	
	if len(lines) > 0 {
		// Parse request line
		parts := strings.Fields(lines[0])
		if len(parts) >= 3 {
			if strings.HasPrefix(parts[2], "HTTP/") {
				// Request
				httpData["http_method"] = parts[0]
				httpData["http_url"] = parts[1]
				httpData["http_version"] = parts[2]
			} else if strings.HasPrefix(parts[0], "HTTP/") {
				// Response
				httpData["http_version"] = parts[0]
				httpData["http_status"] = parts[1]
			}
		}
		
		// Parse headers
		for i := 1; i < len(lines); i++ {
			if lines[i] == "" {
				// Body starts after empty line
				if i+1 < len(lines) {
					body := strings.Join(lines[i+1:], "\r\n")
					httpData["http_body"] = body
					httpData["http_body_bytes"] = len(body)
				}
				break
			}
			
			headerParts := strings.SplitN(lines[i], ":", 2)
			if len(headerParts) == 2 {
				headerName := strings.TrimSpace(headerParts[0])
				headerValue := strings.TrimSpace(headerParts[1])
				
				if strings.ToLower(headerName) == "user-agent" {
					httpData["http_user_agent"] = headerValue
				}
			}
		}
	}
	
	return httpData
}

func (se *SigmaEngine) isPrivateIP(ip string) bool {
	return strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "172.16.") ||
		strings.HasPrefix(ip, "172.17.") ||
		strings.HasPrefix(ip, "172.18.") ||
		strings.HasPrefix(ip, "172.19.") ||
		strings.HasPrefix(ip, "172.20.") ||
		strings.HasPrefix(ip, "172.21.") ||
		strings.HasPrefix(ip, "172.22.") ||
		strings.HasPrefix(ip, "172.23.") ||
		strings.HasPrefix(ip, "172.24.") ||
		strings.HasPrefix(ip, "172.25.") ||
		strings.HasPrefix(ip, "172.26.") ||
		strings.HasPrefix(ip, "172.27.") ||
		strings.HasPrefix(ip, "172.28.") ||
		strings.HasPrefix(ip, "172.29.") ||
		strings.HasPrefix(ip, "172.30.") ||
		strings.HasPrefix(ip, "172.31.")
}

func (se *SigmaEngine) matchRule(rule SigmaRule, data map[string]interface{}) bool {
	if rule.Compiled == nil {
		return false
	}
	
	// Check log source first
	if !se.matchLogSource(rule.LogSource, data) {
		return false
	}
	
	// Evaluate matchers
	matchResults := make(map[string]bool)
	
	for _, matcher := range rule.Compiled.Matchers {
		result := se.evaluateMatcher(matcher, data)
		matchResults[matcher.Field] = result
	}
	
	// Evaluate condition
	return se.evaluateCondition(rule.Compiled.Condition, matchResults)
}

func (se *SigmaEngine) matchLogSource(logSource SigmaLogSource, data map[string]interface{}) bool {
	// Simple log source matching
	switch logSource.Category {
	case "network":
		return true // All packets are network
	case "webserver":
		// Check if it's HTTP traffic
		_, hasMethod := data["http_method"]
		_, hasURL := data["http_url"]
		return hasMethod || hasURL
	case "dns":
		_, hasDNS := data["dns_query"]
		return hasDNS
	case "authentication":
		// Would need auth event data
		_, hasAuth := data["event_action"]
		return hasAuth
	}
	
	return true
}

func (se *SigmaEngine) evaluateMatcher(matcher FieldMatcher, data map[string]interface{}) bool {
	fieldValue, exists := data[matcher.Field]
	if !exists {
		return false
	}
	
	switch matcher.Operator {
	case "equals":
		return se.matchEquals(fieldValue, matcher.Value, matcher.Modifiers)
	case "contains":
		return se.matchContains(fieldValue, matcher.Value, matcher.Modifiers)
	case "startswith":
		return se.matchStartsWith(fieldValue, matcher.Value, matcher.Modifiers)
	case "endswith":
		return se.matchEndsWith(fieldValue, matcher.Value, matcher.Modifiers)
	case "regex":
		return se.matchRegex(fieldValue, matcher.Value)
	case "gt":
		return se.matchGreaterThan(fieldValue, matcher.Value)
	case "lt":
		return se.matchLessThan(fieldValue, matcher.Value)
	case "gte":
		return se.matchGreaterThanOrEqual(fieldValue, matcher.Value)
	case "lte":
		return se.matchLessThanOrEqual(fieldValue, matcher.Value)
	}
	
	return false
}

func (se *SigmaEngine) matchEquals(fieldValue, matchValue interface{}, modifiers []string) bool {
	ignoreCase := se.hasModifier(modifiers, "ignorecase")
	
	// Handle different types
	switch fv := fieldValue.(type) {
	case string:
		mv, ok := matchValue.(string)
		if !ok {
			return false
		}
		if ignoreCase {
			return strings.EqualFold(fv, mv)
		}
		return fv == mv
		
	case int:
		switch mv := matchValue.(type) {
		case int:
			return fv == mv
		case []int:
			for _, v := range mv {
				if fv == v {
					return true
				}
			}
		}
		
	case []string:
		mv, ok := matchValue.(string)
		if !ok {
			return false
		}
		for _, v := range fv {
			if ignoreCase && strings.EqualFold(v, mv) {
				return true
			} else if v == mv {
				return true
			}
		}
	}
	
	return false
}

func (se *SigmaEngine) matchContains(fieldValue, matchValue interface{}, modifiers []string) bool {
	fvStr, ok1 := fieldValue.(string)
	mvStr, ok2 := matchValue.(string)
	
	if !ok1 || !ok2 {
		return false
	}
	
	ignoreCase := se.hasModifier(modifiers, "ignorecase")
	all := se.hasModifier(modifiers, "all")
	any := se.hasModifier(modifiers, "any")
	
	if ignoreCase {
		fvStr = strings.ToLower(fvStr)
		mvStr = strings.ToLower(mvStr)
	}
	
	// Handle array of values
	if mvSlice, ok := matchValue.([]string); ok {
		if all {
			for _, v := range mvSlice {
				if ignoreCase {
					v = strings.ToLower(v)
				}
				if !strings.Contains(fvStr, v) {
					return false
				}
			}
			return true
		} else if any {
			for _, v := range mvSlice {
				if ignoreCase {
					v = strings.ToLower(v)
				}
				if strings.Contains(fvStr, v) {
					return true
				}
			}
			return false
		}
	}
	
	return strings.Contains(fvStr, mvStr)
}

func (se *SigmaEngine) matchStartsWith(fieldValue, matchValue interface{}, modifiers []string) bool {
	fvStr, ok1 := fieldValue.(string)
	mvStr, ok2 := matchValue.(string)
	
	if !ok1 || !ok2 {
		return false
	}
	
	if se.hasModifier(modifiers, "ignorecase") {
		return strings.HasPrefix(strings.ToLower(fvStr), strings.ToLower(mvStr))
	}
	
	return strings.HasPrefix(fvStr, mvStr)
}

func (se *SigmaEngine) matchEndsWith(fieldValue, matchValue interface{}, modifiers []string) bool {
	fvStr, ok1 := fieldValue.(string)
	mvStr, ok2 := matchValue.(string)
	
	if !ok1 || !ok2 {
		return false
	}
	
	if se.hasModifier(modifiers, "ignorecase") {
		return strings.HasSuffix(strings.ToLower(fvStr), strings.ToLower(mvStr))
	}
	
	return strings.HasSuffix(fvStr, mvStr)
}

func (se *SigmaEngine) matchRegex(fieldValue, matchValue interface{}) bool {
	fvStr, ok1 := fieldValue.(string)
	mvStr, ok2 := matchValue.(string)
	
	if !ok1 || !ok2 {
		return false
	}
	
	re, err := regexp.Compile(mvStr)
	if err != nil {
		return false
	}
	
	return re.MatchString(fvStr)
}

func (se *SigmaEngine) matchGreaterThan(fieldValue, matchValue interface{}) bool {
	fvInt, ok1 := se.toInt(fieldValue)
	mvInt, ok2 := se.toInt(matchValue)
	
	if ok1 && ok2 {
		return fvInt > mvInt
	}
	
	return false
}

func (se *SigmaEngine) matchLessThan(fieldValue, matchValue interface{}) bool {
	fvInt, ok1 := se.toInt(fieldValue)
	mvInt, ok2 := se.toInt(matchValue)
	
	if ok1 && ok2 {
		return fvInt < mvInt
	}
	
	return false
}

func (se *SigmaEngine) matchGreaterThanOrEqual(fieldValue, matchValue interface{}) bool {
	fvInt, ok1 := se.toInt(fieldValue)
	mvInt, ok2 := se.toInt(matchValue)
	
	if ok1 && ok2 {
		return fvInt >= mvInt
	}
	
	return false
}

func (se *SigmaEngine) matchLessThanOrEqual(fieldValue, matchValue interface{}) bool {
	fvInt, ok1 := se.toInt(fieldValue)
	mvInt, ok2 := se.toInt(matchValue)
	
	if ok1 && ok2 {
		return fvInt <= mvInt
	}
	
	return false
}

func (se *SigmaEngine) toInt(value interface{}) (int, bool) {
	switch v := value.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	}
	return 0, false
}

func (se *SigmaEngine) hasModifier(modifiers []string, modifier string) bool {
	for _, m := range modifiers {
		if m == modifier {
			return true
		}
	}
	return false
}

func (se *SigmaEngine) evaluateCondition(condition *ConditionEvaluator, results map[string]bool) bool {
	if condition == nil {
		return true
	}
	
	switch condition.Type {
	case "selection":
		// All matchers must be true
		for _, result := range results {
			if !result {
				return false
			}
		}
		return true
		
	case "and":
		// All operands must be true
		for _, result := range results {
			if !result {
				return false
			}
		}
		return true
		
	case "or":
		// Any operand must be true
		for _, result := range results {
			if result {
				return true
			}
		}
		return false
		
	case "not":
		// Invert the result
		for _, result := range results {
			if result {
				return false
			}
		}
		return true
	}
	
	return true
}

func (se *SigmaEngine) createAlert(rule SigmaRule, data map[string]interface{}) SigmaAlert {
	alert := SigmaAlert{
		Timestamp:     time.Now(),
		RuleID:        rule.ID,
		RuleTitle:     rule.Title,
		Level:         rule.Level,
		Tags:          rule.Tags,
		Message:       fmt.Sprintf("%s - %s", rule.Title, rule.Description),
		MatchedFields: make(map[string]interface{}),
		PacketInfo:    data,
		References:    rule.References,
	}
	
	// Extract matched fields
	for _, matcher := range rule.Compiled.Matchers {
		if value, exists := data[matcher.Field]; exists {
			alert.MatchedFields[matcher.Field] = value
		}
	}
	
	return alert
}

// Rule management

func (se *SigmaEngine) AddRule(rule SigmaRule) error {
	if err := se.compileRule(&rule); err != nil {
		return err
	}
	se.rules = append(se.rules, rule)
	return nil
}

func (se *SigmaEngine) LoadRuleFromYAML(yamlContent string) error {
	var rule SigmaRule
	if err := yaml.Unmarshal([]byte(yamlContent), &rule); err != nil {
		return err
	}
	
	return se.AddRule(rule)
}

// Getters

func (se *SigmaEngine) GetAlerts() []SigmaAlert {
	return se.alerts
}

func (se *SigmaEngine) GetAlertsByRule(ruleID string) []SigmaAlert {
	var ruleAlerts []SigmaAlert
	for _, alert := range se.alerts {
		if alert.RuleID == ruleID {
			ruleAlerts = append(ruleAlerts, alert)
		}
	}
	return ruleAlerts
}

func (se *SigmaEngine) GetAlertsByLevel(level string) []SigmaAlert {
	var levelAlerts []SigmaAlert
	for _, alert := range se.alerts {
		if alert.Level == level {
			levelAlerts = append(levelAlerts, alert)
		}
	}
	return levelAlerts
}

func (se *SigmaEngine) GetStats() interface{} {
	return se.stats
}

func (se *SigmaEngine) GetRules() []SigmaRule {
	return se.rules
}

// Cleanup

func (se *SigmaEngine) ClearAlerts() {
	se.alerts = make([]SigmaAlert, 0)
}

func (se *SigmaEngine) GetRecentAlerts(duration time.Duration) []SigmaAlert {
	cutoff := time.Now().Add(-duration)
	var recent []SigmaAlert
	
	for _, alert := range se.alerts {
		if alert.Timestamp.After(cutoff) {
			recent = append(recent, alert)
		}
	}
	
	return recent
}