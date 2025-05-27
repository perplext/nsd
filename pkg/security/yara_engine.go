package security

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// YARAEngine implements YARA rule matching for network traffic
type YARAEngine struct {
	rules   []YARARule
	matches []YARAMatch
	stats   YARAStats
	mu      sync.Mutex
}

type YARARule struct {
	ID          string
	Name        string
	Tags        []string
	Meta        map[string]string
	Strings     []YARAString
	Condition   string
	Imports     []string
	Description string
	Author      string
	Date        string
	Version     string
	ThreatLevel string
}

type YARAString struct {
	ID         string
	Value      string
	Type       string // "text", "hex", "regex"
	Modifiers  []string // "nocase", "wide", "ascii", "fullword", etc.
	Offset     int
	References []string
}

type YARAMatch struct {
	Timestamp   time.Time
	RuleID      string
	RuleName    string
	Tags        []string
	Strings     []StringMatch
	PacketInfo  PacketDetails
	ThreatLevel string
	Meta        map[string]string
}

type StringMatch struct {
	StringID string
	Offset   int
	Length   int
	Data     string
}

type PacketDetails struct {
	SrcIP     string
	DstIP     string
	SrcPort   int
	DstPort   int
	Protocol  string
	Direction string
	Size      int
	Payload   []byte
}

type YARAStats struct {
	TotalPackets    uint64
	TotalMatches    uint64
	MatchesByRule   map[string]uint64
	MatchesByTag    map[string]uint64
	MatchesByThreat map[string]uint64
}

func NewYARAEngine() *YARAEngine {
	engine := &YARAEngine{
		rules:   make([]YARARule, 0),
		matches: make([]YARAMatch, 0),
		stats: YARAStats{
			MatchesByRule:   make(map[string]uint64),
			MatchesByTag:    make(map[string]uint64),
			MatchesByThreat: make(map[string]uint64),
		},
	}
	
	engine.loadDefaultRules()
	return engine
}

func (ye *YARAEngine) loadDefaultRules() {
	// Load default YARA rules for network traffic analysis
	defaultRules := []YARARule{
		{
			ID:          "malware_generic_backdoor",
			Name:        "Generic_Backdoor_Commands",
			Tags:        []string{"backdoor", "malware"},
			ThreatLevel: "high",
			Meta: map[string]string{
				"author":      "NetMon Security",
				"description": "Detects generic backdoor commands",
				"date":        "2024-01-01",
			},
			Strings: []YARAString{
				{ID: "$cmd1", Value: "cmd.exe", Type: "text", Modifiers: []string{"nocase"}},
				{ID: "$cmd2", Value: "/bin/sh", Type: "text"},
				{ID: "$cmd3", Value: "powershell", Type: "text", Modifiers: []string{"nocase"}},
				{ID: "$reverse", Value: "reverse", Type: "text", Modifiers: []string{"nocase"}},
				{ID: "$shell", Value: "shell", Type: "text", Modifiers: []string{"nocase"}},
				{ID: "$connect", Value: "connect", Type: "text", Modifiers: []string{"nocase"}},
			},
			Condition: "any of ($cmd*) and ($reverse or $shell) and $connect",
		},
		{
			ID:          "exploit_sql_injection",
			Name:        "SQL_Injection_Patterns",
			Tags:        []string{"sqli", "exploit", "web"},
			ThreatLevel: "high",
			Meta: map[string]string{
				"author":      "NetMon Security",
				"description": "Detects SQL injection attempts",
			},
			Strings: []YARAString{
				{ID: "$union", Value: "union select", Type: "text", Modifiers: []string{"nocase"}},
				{ID: "$sqli1", Value: "' or '1'='1", Type: "text"},
				{ID: "$sqli2", Value: "\" or \"1\"=\"1", Type: "text"},
				{ID: "$sqli3", Value: "'; drop table", Type: "text", Modifiers: []string{"nocase"}},
				{ID: "$sqli4", Value: "--", Type: "text"},
				{ID: "$sqli5", Value: "/**/", Type: "text"},
				{ID: "$sqli6", Value: "0x[0-9a-fA-F]+", Type: "regex"},
			},
			Condition: "$union or any of ($sqli*)",
		},
		{
			ID:          "exploit_xss",
			Name:        "XSS_Attack_Patterns",
			Tags:        []string{"xss", "exploit", "web"},
			ThreatLevel: "medium",
			Meta: map[string]string{
				"author":      "NetMon Security",
				"description": "Detects XSS attack patterns",
			},
			Strings: []YARAString{
				{ID: "$script1", Value: "<script", Type: "text", Modifiers: []string{"nocase"}},
				{ID: "$script2", Value: "javascript:", Type: "text", Modifiers: []string{"nocase"}},
				{ID: "$onerror", Value: "onerror=", Type: "text", Modifiers: []string{"nocase"}},
				{ID: "$onload", Value: "onload=", Type: "text", Modifiers: []string{"nocase"}},
				{ID: "$alert", Value: "alert(", Type: "text"},
				{ID: "$eval", Value: "eval(", Type: "text"},
			},
			Condition: "any of them",
		},
		{
			ID:          "malware_cryptominer",
			Name:        "Cryptocurrency_Miner",
			Tags:        []string{"cryptominer", "malware"},
			ThreatLevel: "medium",
			Meta: map[string]string{
				"author":      "NetMon Security",
				"description": "Detects cryptocurrency mining activity",
			},
			Strings: []YARAString{
				{ID: "$stratum", Value: "stratum+tcp://", Type: "text"},
				{ID: "$pool1", Value: "pool.minergate", Type: "text", Modifiers: []string{"nocase"}},
				{ID: "$pool2", Value: "xmrpool", Type: "text", Modifiers: []string{"nocase"}},
				{ID: "$worker", Value: "\"worker\"", Type: "text"},
				{ID: "$monero", Value: "monero", Type: "text", Modifiers: []string{"nocase"}},
				{ID: "$coinhive", Value: "coinhive", Type: "text", Modifiers: []string{"nocase"}},
			},
			Condition: "$stratum or (any of ($pool*) and $worker) or $coinhive",
		},
		{
			ID:          "malware_ransomware",
			Name:        "Ransomware_Indicators",
			Tags:        []string{"ransomware", "malware"},
			ThreatLevel: "critical",
			Meta: map[string]string{
				"author":      "NetMon Security",
				"description": "Detects ransomware indicators",
			},
			Strings: []YARAString{
				{ID: "$ransom1", Value: "Your files have been encrypted", Type: "text", Modifiers: []string{"nocase"}},
				{ID: "$ransom2", Value: "bitcoin", Type: "text", Modifiers: []string{"nocase"}},
				{ID: "$ransom3", Value: "decrypt", Type: "text", Modifiers: []string{"nocase"}},
				{ID: "$ransom4", Value: ".locked", Type: "text"},
				{ID: "$ransom5", Value: ".encrypted", Type: "text"},
				{ID: "$aes", Value: "AES", Type: "text"},
				{ID: "$rsa", Value: "RSA", Type: "text"},
			},
			Condition: "$ransom1 or ($ransom2 and $ransom3) or (2 of ($ransom*))",
		},
		{
			ID:          "protocol_anomaly_dns",
			Name:        "DNS_Tunneling_Detection",
			Tags:        []string{"dns", "tunneling", "anomaly"},
			ThreatLevel: "medium",
			Meta: map[string]string{
				"author":      "NetMon Security",
				"description": "Detects potential DNS tunneling",
			},
			Strings: []YARAString{
				{ID: "$dns_header", Value: "00000100", Type: "hex"},
				{ID: "$long_domain", Value: "[a-zA-Z0-9]{50,}", Type: "regex"},
				{ID: "$base64", Value: "[A-Za-z0-9+/]{20,}={0,2}", Type: "regex"},
				{ID: "$txt_query", Value: "0010", Type: "hex"},
			},
			Condition: "$dns_header and ($long_domain or $base64)",
		},
		{
			ID:          "malware_webshell",
			Name:        "Webshell_Detection",
			Tags:        []string{"webshell", "backdoor"},
			ThreatLevel: "high",
			Meta: map[string]string{
				"author":      "NetMon Security",
				"description": "Detects webshell patterns",
			},
			Strings: []YARAString{
				{ID: "$eval", Value: "eval(", Type: "text"},
				{ID: "$base64", Value: "base64_decode", Type: "text"},
				{ID: "$system", Value: "system(", Type: "text"},
				{ID: "$exec", Value: "exec(", Type: "text"},
				{ID: "$passthru", Value: "passthru(", Type: "text"},
				{ID: "$cmd", Value: "$_REQUEST", Type: "text"},
				{ID: "$post", Value: "$_POST", Type: "text"},
			},
			Condition: "($eval or $base64) and any of ($system, $exec, $passthru) and any of ($cmd, $post)",
		},
		{
			ID:          "exploit_log4j",
			Name:        "Log4j_Exploit_Attempt",
			Tags:        []string{"log4j", "exploit", "cve-2021-44228"},
			ThreatLevel: "critical",
			Meta: map[string]string{
				"author":      "NetMon Security",
				"description": "Detects Log4j exploit attempts",
				"reference":   "CVE-2021-44228",
			},
			Strings: []YARAString{
				{ID: "$jndi", Value: "${jndi:", Type: "text"},
				{ID: "$ldap", Value: "ldap://", Type: "text"},
				{ID: "$rmi", Value: "rmi://", Type: "text"},
				{ID: "$dns", Value: "dns://", Type: "text"},
				{ID: "$lower", Value: "${lower:", Type: "text"},
				{ID: "$upper", Value: "${upper:", Type: "text"},
			},
			Condition: "$jndi and any of ($ldap, $rmi, $dns)",
		},
		{
			ID:          "malware_c2_communication",
			Name:        "C2_Communication_Patterns",
			Tags:        []string{"c2", "malware", "communication"},
			ThreatLevel: "high",
			Meta: map[string]string{
				"author":      "NetMon Security",
				"description": "Detects command and control communication",
			},
			Strings: []YARAString{
				{ID: "$beacon", Value: "beacon", Type: "text", Modifiers: []string{"nocase"}},
				{ID: "$checkin", Value: "check-in", Type: "text", Modifiers: []string{"nocase"}},
				{ID: "$agent", Value: "agent", Type: "text", Modifiers: []string{"nocase"}},
				{ID: "$bot_id", Value: "bot_id", Type: "text"},
				{ID: "$command", Value: "command", Type: "text"},
				{ID: "$base64", Value: "[A-Za-z0-9+/]{100,}={0,2}", Type: "regex"},
			},
			Condition: "2 of them",
		},
		{
			ID:          "data_exfiltration",
			Name:        "Data_Exfiltration_Patterns",
			Tags:        []string{"exfiltration", "data_theft"},
			ThreatLevel: "high",
			Meta: map[string]string{
				"author":      "NetMon Security",
				"description": "Detects potential data exfiltration",
			},
			Strings: []YARAString{
				{ID: "$zip_header", Value: "PK", Type: "text"},
				{ID: "$rar_header", Value: "Rar!", Type: "text"},
				{ID: "$7z_header", Value: "377abcaf271c", Type: "hex"},
				{ID: "$password", Value: "password", Type: "text", Modifiers: []string{"nocase"}},
				{ID: "$credential", Value: "credential", Type: "text", Modifiers: []string{"nocase"}},
				{ID: "$secret", Value: "secret", Type: "text", Modifiers: []string{"nocase"}},
				{ID: "$api_key", Value: "api_key", Type: "text", Modifiers: []string{"nocase"}},
			},
			Condition: "any of ($*_header) and any of ($password, $credential, $secret, $api_key)",
		},
	}
	
	ye.rules = defaultRules
}

func (ye *YARAEngine) ProcessPacket(packet gopacket.Packet) []YARAMatch {
	ye.stats.TotalPackets++
	
	// Extract packet details
	details := ye.extractPacketDetails(packet)
	if details.Payload == nil || len(details.Payload) == 0 {
		return nil
	}
	
	var matches []YARAMatch
	
	// Check each rule against the packet
	for _, rule := range ye.rules {
		if match := ye.matchRule(rule, details); match != nil {
			matches = append(matches, *match)
			ye.matches = append(ye.matches, *match)
			
			ye.stats.TotalMatches++
			ye.stats.MatchesByRule[rule.ID]++
			
			for _, tag := range rule.Tags {
				ye.stats.MatchesByTag[tag]++
			}
			
			ye.stats.MatchesByThreat[rule.ThreatLevel]++
		}
	}
	
	return matches
}

func (ye *YARAEngine) extractPacketDetails(packet gopacket.Packet) PacketDetails {
	details := PacketDetails{
		Size: len(packet.Data()),
	}
	
	// Extract network layer info
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		details.SrcIP = netLayer.NetworkFlow().Src().String()
		details.DstIP = netLayer.NetworkFlow().Dst().String()
	}
	
	// Extract transport layer info
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		details.SrcPort = int(tcp.SrcPort)
		details.DstPort = int(tcp.DstPort)
		details.Protocol = "TCP"
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		details.SrcPort = int(udp.SrcPort)
		details.DstPort = int(udp.DstPort)
		details.Protocol = "UDP"
	}
	
	// Extract payload
	if app := packet.ApplicationLayer(); app != nil {
		details.Payload = app.Payload()
	} else if transport := packet.TransportLayer(); transport != nil {
		details.Payload = transport.LayerPayload()
	}
	
	// Determine direction (simplified)
	if details.DstPort < 1024 {
		details.Direction = "to_server"
	} else {
		details.Direction = "to_client"
	}
	
	return details
}

func (ye *YARAEngine) matchRule(rule YARARule, details PacketDetails) *YARAMatch {
	stringMatches := make(map[string][]StringMatch)
	
	// Check each string in the rule
	for _, str := range rule.Strings {
		if matches := ye.matchString(str, details.Payload); len(matches) > 0 {
			stringMatches[str.ID] = matches
		}
	}
	
	// Evaluate condition
	if ye.evaluateCondition(rule.Condition, stringMatches, rule.Strings) {
		match := &YARAMatch{
			Timestamp:   time.Now(),
			RuleID:      rule.ID,
			RuleName:    rule.Name,
			Tags:        rule.Tags,
			Strings:     ye.flattenMatches(stringMatches),
			PacketInfo:  details,
			ThreatLevel: rule.ThreatLevel,
			Meta:        rule.Meta,
		}
		
		return match
	}
	
	return nil
}

func (ye *YARAEngine) matchString(str YARAString, payload []byte) []StringMatch {
	var matches []StringMatch
	
	switch str.Type {
	case "text":
		matches = ye.matchTextString(str, payload)
	case "hex":
		matches = ye.matchHexString(str, payload)
	case "regex":
		matches = ye.matchRegexString(str, payload)
	}
	
	return matches
}

func (ye *YARAEngine) matchTextString(str YARAString, payload []byte) []StringMatch {
	var matches []StringMatch
	searchStr := str.Value
	payloadStr := string(payload)
	
	// Apply modifiers
	nocase := false
	fullword := false
	for _, mod := range str.Modifiers {
		switch mod {
		case "nocase":
			nocase = true
		case "fullword":
			fullword = true
		}
	}
	
	if nocase {
		searchStr = strings.ToLower(searchStr)
		payloadStr = strings.ToLower(payloadStr)
	}
	
	// Find all occurrences
	start := 0
	for {
		index := strings.Index(payloadStr[start:], searchStr)
		if index == -1 {
			break
		}
		
		actualIndex := start + index
		
		// Check fullword modifier
		if fullword {
			if actualIndex > 0 && isWordChar(payloadStr[actualIndex-1]) {
				start = actualIndex + 1
				continue
			}
			if actualIndex+len(searchStr) < len(payloadStr) && isWordChar(payloadStr[actualIndex+len(searchStr)]) {
				start = actualIndex + 1
				continue
			}
		}
		
		match := StringMatch{
			StringID: str.ID,
			Offset:   actualIndex,
			Length:   len(str.Value),
			Data:     str.Value,
		}
		matches = append(matches, match)
		
		start = actualIndex + 1
	}
	
	return matches
}

func (ye *YARAEngine) matchHexString(str YARAString, payload []byte) []StringMatch {
	var matches []StringMatch
	
	// Parse hex string
	hexBytes, err := ye.parseHexString(str.Value)
	if err != nil {
		return matches
	}
	
	// Find all occurrences
	for i := 0; i <= len(payload)-len(hexBytes); i++ {
		if bytes.Equal(payload[i:i+len(hexBytes)], hexBytes) {
			match := StringMatch{
				StringID: str.ID,
				Offset:   i,
				Length:   len(hexBytes),
				Data:     hex.EncodeToString(hexBytes),
			}
			matches = append(matches, match)
		}
	}
	
	return matches
}

func (ye *YARAEngine) matchRegexString(str YARAString, payload []byte) []StringMatch {
	var matches []StringMatch
	
	re, err := regexp.Compile(str.Value)
	if err != nil {
		return matches
	}
	
	allMatches := re.FindAllIndex(payload, -1)
	for _, match := range allMatches {
		stringMatch := StringMatch{
			StringID: str.ID,
			Offset:   match[0],
			Length:   match[1] - match[0],
			Data:     string(payload[match[0]:match[1]]),
		}
		matches = append(matches, stringMatch)
	}
	
	return matches
}

func (ye *YARAEngine) evaluateCondition(condition string, matches map[string][]StringMatch, yaraStrings []YARAString) bool {
	// Simplified condition evaluation
	condition = strings.TrimSpace(condition)
	
	// Handle "any of them"
	if condition == "any of them" {
		return len(matches) > 0
	}
	
	// Handle "all of them"
	if condition == "all of them" {
		return len(matches) == len(yaraStrings)
	}
	
	// Handle "n of them"
	if strings.HasPrefix(condition, "2 of them") {
		return len(matches) >= 2
	}
	
	// Handle specific string references
	if strings.Contains(condition, " or ") {
		parts := strings.Split(condition, " or ")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if ye.evaluateSimpleCondition(part, matches) {
				return true
			}
		}
		return false
	}
	
	if strings.Contains(condition, " and ") {
		parts := strings.Split(condition, " and ")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if !ye.evaluateSimpleCondition(part, matches) {
				return false
			}
		}
		return true
	}
	
	// Single condition
	return ye.evaluateSimpleCondition(condition, matches)
}

func (ye *YARAEngine) evaluateSimpleCondition(condition string, matches map[string][]StringMatch) bool {
	// Handle wildcards like ($cmd*)
	if strings.Contains(condition, "*") {
		// Extract pattern
		pattern := strings.Trim(condition, "()")
		prefix := strings.TrimSuffix(pattern, "*")
		
		if strings.HasPrefix(condition, "any of") {
			// "any of ($cmd*)"
			for stringID := range matches {
				if strings.HasPrefix(stringID, prefix) {
					return true
				}
			}
			return false
		}
		
		// Count matches
		count := 0
		for stringID := range matches {
			if strings.HasPrefix(stringID, prefix) {
				count++
			}
		}
		
		// Check if we have a numeric requirement
		if strings.Contains(condition, "2 of") {
			return count >= 2
		}
		
		return count > 0
	}
	
	// Direct string reference
	stringID := strings.TrimSpace(condition)
	_, found := matches[stringID]
	return found
}

func (ye *YARAEngine) parseHexString(hexStr string) ([]byte, error) {
	// Remove brackets and spaces
	hexStr = strings.Trim(hexStr, "{}")
	hexStr = strings.ReplaceAll(hexStr, " ", "")
	hexStr = strings.ReplaceAll(hexStr, "0x", "")
	hexStr = strings.ReplaceAll(hexStr, ",", "")
	
	return hex.DecodeString(hexStr)
}

func (ye *YARAEngine) flattenMatches(stringMatches map[string][]StringMatch) []StringMatch {
	var flattened []StringMatch
	for _, matches := range stringMatches {
		flattened = append(flattened, matches...)
	}
	return flattened
}

func isWordChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

// Rule management

func (ye *YARAEngine) AddRule(rule YARARule) {
	ye.rules = append(ye.rules, rule)
}

func (ye *YARAEngine) LoadRulesFromString(rulesStr string) error {
	// Parse YARA rules from string (simplified)
	// In a real implementation, this would use a proper YARA parser
	return fmt.Errorf("YARA rule parsing not implemented")
}

// Getters

func (ye *YARAEngine) GetMatches() []YARAMatch {
	return ye.matches
}

func (ye *YARAEngine) GetMatchesByRule(ruleID string) []YARAMatch {
	var ruleMatches []YARAMatch
	for _, match := range ye.matches {
		if match.RuleID == ruleID {
			ruleMatches = append(ruleMatches, match)
		}
	}
	return ruleMatches
}

func (ye *YARAEngine) GetMatchesByTag(tag string) []YARAMatch {
	var tagMatches []YARAMatch
	for _, match := range ye.matches {
		for _, t := range match.Tags {
			if t == tag {
				tagMatches = append(tagMatches, match)
				break
			}
		}
	}
	return tagMatches
}

func (ye *YARAEngine) GetMatchesByThreatLevel(level string) []YARAMatch {
	var threatMatches []YARAMatch
	for _, match := range ye.matches {
		if match.ThreatLevel == level {
			threatMatches = append(threatMatches, match)
		}
	}
	return threatMatches
}

func (ye *YARAEngine) GetStats() interface{} {
	return ye.stats
}

func (ye *YARAEngine) ClearAlerts() {
	ye.mu.Lock()
	defer ye.mu.Unlock()
	ye.matches = make([]YARAMatch, 0)
}

func (ye *YARAEngine) GetRules() []YARARule {
	return ye.rules
}

// Cleanup

func (ye *YARAEngine) ClearMatches() {
	ye.matches = make([]YARAMatch, 0)
}

func (ye *YARAEngine) GetRecentMatches(duration time.Duration) []YARAMatch {
	cutoff := time.Now().Add(-duration)
	var recent []YARAMatch
	
	for _, match := range ye.matches {
		if match.Timestamp.After(cutoff) {
			recent = append(recent, match)
		}
	}
	
	return recent
}