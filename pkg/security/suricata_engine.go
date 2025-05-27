package security

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// SuricataEngine implements Suricata IDS rule processing
type SuricataEngine struct {
	rules      []SuricataRule
	alerts     []SuricataAlert
	stats      SuricataStats
	flowTable  map[string]*FlowState
	eveFormat  bool // Output in EVE JSON format
}

type SuricataRule struct {
	ID           int
	Action       string // alert, pass, drop, reject, rejectsrc, rejectdst, rejectboth
	Protocol     string
	SrcIP        string
	SrcPort      string
	Direction    string // ->, <>, <-
	DstIP        string
	DstPort      string
	Options      map[string][]string // Suricata supports multiple values per option
	Message      string
	Classtype    string
	Priority     int
	SID          int
	Rev          int
	GID          int
	Metadata     []string
	Reference    []string
	FlowBits     []string
	Threshold    *ThresholdConfig
	Detection    *DetectionConfig
	Raw          string
}

type ThresholdConfig struct {
	Type     string // threshold, limit, both
	Track    string // by_src, by_dst
	Count    int
	Seconds  int
}

type DetectionConfig struct {
	FastPattern  bool
	Nocase       bool
	Depth        int
	Offset       int
	Distance     int
	Within       int
	HTTPModifier string // http_uri, http_header, http_cookie, etc.
}

type FlowState struct {
	ID           string
	Protocol     string
	SrcIP        net.IP
	DstIP        net.IP
	SrcPort      uint16
	DstPort      uint16
	State        string
	Packets      int
	Bytes        int64
	StartTime    time.Time
	LastActivity time.Time
	FlowBits     map[string]bool
}

type SuricataAlert struct {
	Timestamp    time.Time              `json:"timestamp"`
	FlowID       string                 `json:"flow_id,omitempty"`
	EventType    string                 `json:"event_type"`
	SrcIP        string                 `json:"src_ip"`
	SrcPort      int                    `json:"src_port"`
	DstIP        string                 `json:"dest_ip"`
	DstPort      int                    `json:"dest_port"`
	Protocol     string                 `json:"proto"`
	Alert        *AlertInfo             `json:"alert"`
	Flow         *FlowInfo              `json:"flow,omitempty"`
	PacketInfo   *SuricataPacketInfo            `json:"packet_info,omitempty"`
	HTTP         map[string]interface{} `json:"http,omitempty"`
	DNS          map[string]interface{} `json:"dns,omitempty"`
	TLS          map[string]interface{} `json:"tls,omitempty"`
}

type AlertInfo struct {
	Action      string   `json:"action"`
	GID         int      `json:"gid"`
	SignatureID int      `json:"signature_id"`
	Rev         int      `json:"rev"`
	Signature   string   `json:"signature"`
	Category    string   `json:"category"`
	Severity    int      `json:"severity"`
	Metadata    []string `json:"metadata,omitempty"`
}

type FlowInfo struct {
	PktsToServer int    `json:"pkts_toserver"`
	PktsToClient int    `json:"pkts_toclient"`
	BytesToServer int64 `json:"bytes_toserver"`
	BytesToClient int64 `json:"bytes_toclient"`
	Start        string `json:"start"`
	Duration     int    `json:"duration"`
	State        string `json:"state"`
}

type SuricataPacketInfo struct {
	Linktype  int `json:"linktype"`
	Direction string `json:"direction"`
}

type SuricataStats struct {
	TotalPackets     uint64
	TotalAlerts      uint64
	TotalFlows       uint64
	ActiveFlows      uint64
	ClosedFlows      uint64
	AlertsByRule     map[int]uint64
	AlertsBySeverity map[int]uint64
	ProtocolStats    map[string]uint64
}

func NewSuricataEngine(eveFormat bool) *SuricataEngine {
	engine := &SuricataEngine{
		rules:     make([]SuricataRule, 0),
		alerts:    make([]SuricataAlert, 0),
		flowTable: make(map[string]*FlowState),
		eveFormat: eveFormat,
		stats: SuricataStats{
			AlertsByRule:     make(map[int]uint64),
			AlertsBySeverity: make(map[int]uint64),
			ProtocolStats:    make(map[string]uint64),
		},
	}
	
	engine.loadDefaultRules()
	return engine
}

func (se *SuricataEngine) loadDefaultRules() {
	defaultRules := []string{
		// Emerging Threats style rules
		`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Suspicious User-Agent"; content:"User-Agent|3a 20|"; http_header; content:"bot"; http_header; fast_pattern; classtype:trojan-activity; sid:2000001; rev:1;)`,
		`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"ET EXPLOIT SMB EternalBlue Exploit"; content:"|ff|SMB"; depth:4; offset:4; content:"|00 00 00 00|"; within:4; flow:to_server,established; classtype:attempted-admin; sid:2000002; rev:1;)`,
		
		// Protocol anomaly detection
		`alert tcp any any -> any any (msg:"SURICATA TCP invalid flags"; flags:FPU; classtype:protocol-command-decode; sid:2000003; rev:1;)`,
		`alert dns any any -> any any (msg:"SURICATA DNS malformed query"; dns_query; content:"|00 00|"; depth:2; classtype:protocol-command-decode; sid:2000004; rev:1;)`,
		
		// Application layer detection
		`alert http any any -> any any (msg:"SURICATA HTTP POST without Content-Length"; flow:established,to_server; content:"POST"; http_method; http_header_names; content:!"Content-Length"; classtype:protocol-command-decode; sid:2000005; rev:1;)`,
		`alert tls any any -> any any (msg:"SURICATA TLS invalid version"; tls.version:!"1.0","1.1","1.2","1.3"; classtype:protocol-command-decode; sid:2000006; rev:1;)`,
		
		// File extraction and analysis
		`alert http any any -> any any (msg:"SURICATA Executable file download"; flow:established,to_client; content:"MZ"; depth:2; http_server_body; file_data; classtype:policy-violation; sid:2000007; rev:1;)`,
		`alert smtp any any -> any any (msg:"SURICATA SMTP suspicious attachment"; flow:established; content:"filename="; content:".exe"; within:20; classtype:policy-violation; sid:2000008; rev:1;)`,
		
		// Advanced flow tracking
		`alert tcp any any -> any any (msg:"SURICATA Port scan detected"; flow:stateless; flags:S; threshold:type both, track by_src, count 20, seconds 60; classtype:attempted-recon; sid:2000009; rev:1;)`,
		`alert tcp any any -> any 22 (msg:"SURICATA SSH brute force"; flow:to_server,established; content:"SSH-"; depth:4; threshold:type both, track by_src, count 5, seconds 300; classtype:attempted-user; sid:2000010; rev:1;)`,
		
		// Lua script integration examples
		`alert http any any -> any any (msg:"SURICATA Complex HTTP attack"; flow:established,to_server; content:"eval("; http_uri; lua:complex_http_check.lua; classtype:web-application-attack; sid:2000011; rev:1;)`,
		
		// Stream reassembly detection
		`alert tcp any any -> any any (msg:"SURICATA Large data transfer"; flow:established; stream_size:server,>,10485760; classtype:policy-violation; sid:2000012; rev:1;)`,
		
		// IP reputation and geoip
		`alert ip any any -> any any (msg:"SURICATA Blacklisted IP"; iprep:src,blacklist,>,80; classtype:misc-attack; sid:2000013; rev:1;)`,
		
		// Dataset lookups
		`alert dns any any -> any any (msg:"SURICATA DNS query to malicious domain"; dns_query; dataset:isset,malicious-domains,type string,state dns.query; classtype:trojan-activity; sid:2000014; rev:1;)`,
	}
	
	for _, ruleStr := range defaultRules {
		if rule := se.parseRule(ruleStr); rule != nil {
			se.AddRule(*rule)
		}
	}
}

func (se *SuricataEngine) parseRule(ruleStr string) *SuricataRule {
	ruleStr = strings.TrimSpace(ruleStr)
	if ruleStr == "" || strings.HasPrefix(ruleStr, "#") {
		return nil
	}
	
	// Split into header and options
	parts := strings.SplitN(ruleStr, "(", 2)
	if len(parts) != 2 {
		return nil
	}
	
	header := strings.TrimSpace(parts[0])
	optionsStr := strings.TrimSuffix(strings.TrimSpace(parts[1]), ")")
	
	// Parse header
	headerParts := strings.Fields(header)
	if len(headerParts) < 7 {
		return nil
	}
	
	rule := &SuricataRule{
		Action:    headerParts[0],
		Protocol:  headerParts[1],
		SrcIP:     headerParts[2],
		SrcPort:   headerParts[3],
		Direction: headerParts[4],
		DstIP:     headerParts[5],
		DstPort:   headerParts[6],
		Options:   make(map[string][]string),
		Raw:       ruleStr,
		GID:       1, // Default generator ID
	}
	
	// Parse options (Suricata has more complex option syntax)
	se.parseSuricataOptions(rule, optionsStr)
	
	return rule
}

func (se *SuricataEngine) parseSuricataOptions(rule *SuricataRule, optionsStr string) {
	options := se.splitOptions(optionsStr)
	
	for _, option := range options {
		option = strings.TrimSpace(option)
		if option == "" {
			continue
		}
		
		if strings.Contains(option, ":") {
			parts := strings.SplitN(option, ":", 2)
			key := strings.TrimSpace(parts[0])
			value := strings.Trim(strings.TrimSpace(parts[1]), `"`)
			
			// Handle multi-value options
			if existing, ok := rule.Options[key]; ok {
				rule.Options[key] = append(existing, value)
			} else {
				rule.Options[key] = []string{value}
			}
			
			// Handle special options
			switch key {
			case "msg":
				rule.Message = value
			case "classtype":
				rule.Classtype = value
			case "sid":
				if sid, err := strconv.Atoi(value); err == nil {
					rule.SID = sid
				}
			case "priority":
				if priority, err := strconv.Atoi(value); err == nil {
					rule.Priority = priority
				}
			case "rev":
				if rev, err := strconv.Atoi(value); err == nil {
					rule.Rev = rev
				}
			case "gid":
				if gid, err := strconv.Atoi(value); err == nil {
					rule.GID = gid
				}
			case "metadata":
				rule.Metadata = strings.Split(value, ",")
			case "reference":
				rule.Reference = append(rule.Reference, value)
			case "threshold":
				se.parseThreshold(rule, value)
			}
		} else {
			// Standalone options
			rule.Options[option] = []string{""}
		}
	}
}

func (se *SuricataEngine) parseThreshold(rule *SuricataRule, value string) {
	threshold := &ThresholdConfig{}
	parts := strings.Split(value, ",")
	
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, " ") {
			kv := strings.SplitN(part, " ", 2)
			switch kv[0] {
			case "type":
				threshold.Type = kv[1]
			case "track":
				threshold.Track = kv[1]
			case "count":
				threshold.Count, _ = strconv.Atoi(kv[1])
			case "seconds":
				threshold.Seconds, _ = strconv.Atoi(kv[1])
			}
		}
	}
	
	rule.Threshold = threshold
}

func (se *SuricataEngine) splitOptions(optionsStr string) []string {
	var options []string
	var current strings.Builder
	inQuotes := false
	depth := 0
	
	for _, char := range optionsStr {
		switch char {
		case '"':
			inQuotes = !inQuotes
			current.WriteRune(char)
		case '(':
			if !inQuotes {
				depth++
			}
			current.WriteRune(char)
		case ')':
			if !inQuotes {
				depth--
			}
			current.WriteRune(char)
		case ';':
			if !inQuotes && depth == 0 {
				options = append(options, current.String())
				current.Reset()
			} else {
				current.WriteRune(char)
			}
		default:
			current.WriteRune(char)
		}
	}
	
	if current.Len() > 0 {
		options = append(options, current.String())
	}
	
	return options
}

func (se *SuricataEngine) AddRule(rule SuricataRule) {
	rule.ID = len(se.rules)
	se.rules = append(se.rules, rule)
}

func (se *SuricataEngine) ProcessPacket(packet gopacket.Packet) []SuricataAlert {
	se.stats.TotalPackets++
	
	// Update flow state
	flow := se.updateFlowState(packet)
	
	var alerts []SuricataAlert
	
	for _, rule := range se.rules {
		if se.matchRule(rule, packet, flow) {
			alert := se.createAlert(rule, packet, flow)
			alerts = append(alerts, alert)
			se.alerts = append(se.alerts, alert)
			
			se.stats.TotalAlerts++
			se.stats.AlertsByRule[rule.SID]++
			se.stats.AlertsBySeverity[rule.Priority]++
		}
	}
	
	return alerts
}

func (se *SuricataEngine) updateFlowState(packet gopacket.Packet) *FlowState {
	flowID := se.getFlowID(packet)
	if flowID == "" {
		return nil
	}
	
	flow, exists := se.flowTable[flowID]
	if !exists {
		flow = se.createNewFlow(flowID, packet)
		se.flowTable[flowID] = flow
		se.stats.TotalFlows++
		se.stats.ActiveFlows++
	}
	
	flow.Packets++
	flow.LastActivity = time.Now()
	
	// Update protocol stats
	se.stats.ProtocolStats[flow.Protocol]++
	
	// Calculate packet size
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		flow.Bytes += int64(len(netLayer.LayerPayload()))
	}
	
	return flow
}

func (se *SuricataEngine) getFlowID(packet gopacket.Packet) string {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return ""
	}
	
	src := netLayer.NetworkFlow().Src().String()
	dst := netLayer.NetworkFlow().Dst().String()
	
	var srcPort, dstPort uint16
	var protocol string
	
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		protocol = "tcp"
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
		protocol = "udp"
	} else {
		protocol = "other"
	}
	
	// Create bidirectional flow ID
	if src < dst || (src == dst && srcPort < dstPort) {
		return fmt.Sprintf("%s:%s:%d:%s:%d", protocol, src, srcPort, dst, dstPort)
	}
	return fmt.Sprintf("%s:%s:%d:%s:%d", protocol, dst, dstPort, src, srcPort)
}

func (se *SuricataEngine) createNewFlow(flowID string, packet gopacket.Packet) *FlowState {
	netLayer := packet.NetworkLayer()
	
	flow := &FlowState{
		ID:        flowID,
		SrcIP:     net.ParseIP(netLayer.NetworkFlow().Src().String()),
		DstIP:     net.ParseIP(netLayer.NetworkFlow().Dst().String()),
		StartTime: time.Now(),
		FlowBits:  make(map[string]bool),
		State:     "new",
	}
	
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		flow.Protocol = "tcp"
		flow.SrcPort = uint16(tcp.SrcPort)
		flow.DstPort = uint16(tcp.DstPort)
		
		// Track TCP state
		if tcp.SYN && !tcp.ACK {
			flow.State = "syn_sent"
		} else if tcp.SYN && tcp.ACK {
			flow.State = "syn_ack"
		} else if tcp.ACK {
			flow.State = "established"
		}
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		flow.Protocol = "udp"
		flow.SrcPort = uint16(udp.SrcPort)
		flow.DstPort = uint16(udp.DstPort)
		flow.State = "active"
	}
	
	return flow
}

func (se *SuricataEngine) matchRule(rule SuricataRule, packet gopacket.Packet, flow *FlowState) bool {
	// Check protocol
	if !se.matchProtocol(rule.Protocol, packet) {
		return false
	}
	
	// Check network conditions
	if !se.matchNetwork(rule, packet) {
		return false
	}
	
	// Check Suricata-specific options
	return se.matchSuricataOptions(rule, packet, flow)
}

func (se *SuricataEngine) matchProtocol(protocol string, packet gopacket.Packet) bool {
	switch strings.ToLower(protocol) {
	case "tcp":
		return packet.Layer(layers.LayerTypeTCP) != nil
	case "udp":
		return packet.Layer(layers.LayerTypeUDP) != nil
	case "icmp":
		return packet.Layer(layers.LayerTypeICMPv4) != nil
	case "http":
		// Check for HTTP traffic on common ports
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			return tcp.DstPort == 80 || tcp.SrcPort == 80 || 
			       tcp.DstPort == 8080 || tcp.SrcPort == 8080
		}
		return false
	case "tls":
		// Check for TLS/HTTPS traffic
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			return tcp.DstPort == 443 || tcp.SrcPort == 443
		}
		return false
	case "dns":
		// Check for DNS traffic
		return packet.Layer(layers.LayerTypeDNS) != nil
	case "smtp":
		// Check for SMTP traffic
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			return tcp.DstPort == 25 || tcp.SrcPort == 25 ||
			       tcp.DstPort == 587 || tcp.SrcPort == 587
		}
		return false
	case "ip":
		return packet.NetworkLayer() != nil
	default:
		return true
	}
}

func (se *SuricataEngine) matchNetwork(rule SuricataRule, packet gopacket.Packet) bool {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return false
	}
	
	srcIP := netLayer.NetworkFlow().Src().String()
	dstIP := netLayer.NetworkFlow().Dst().String()
	
	// Handle Suricata variables
	srcIPMatch := se.matchIPWithVariables(rule.SrcIP, srcIP)
	dstIPMatch := se.matchIPWithVariables(rule.DstIP, dstIP)
	
	// Handle bidirectional rules
	if rule.Direction == "<>" {
		return (srcIPMatch && dstIPMatch) || (se.matchIPWithVariables(rule.SrcIP, dstIP) && se.matchIPWithVariables(rule.DstIP, srcIP))
	}
	
	return srcIPMatch && dstIPMatch
}

func (se *SuricataEngine) matchIPWithVariables(ruleIP, packetIP string) bool {
	// Handle Suricata variables
	switch ruleIP {
	case "any":
		return true
	case "$HOME_NET":
		// Check if IP is in home network (simplified)
		return strings.HasPrefix(packetIP, "192.168.") || 
		       strings.HasPrefix(packetIP, "10.") ||
		       strings.HasPrefix(packetIP, "172.")
	case "$EXTERNAL_NET":
		// Check if IP is external
		return !strings.HasPrefix(packetIP, "192.168.") && 
		       !strings.HasPrefix(packetIP, "10.") &&
		       !strings.HasPrefix(packetIP, "172.")
	default:
		// Handle CIDR and regular IPs
		if strings.Contains(ruleIP, "/") {
			_, network, err := net.ParseCIDR(ruleIP)
			if err != nil {
				return false
			}
			ip := net.ParseIP(packetIP)
			return network.Contains(ip)
		}
		return ruleIP == packetIP
	}
}

func (se *SuricataEngine) matchSuricataOptions(rule SuricataRule, packet gopacket.Packet, flow *FlowState) bool {
	payload := se.getPacketPayload(packet)
	
	// Check flow options first
	if flowOpts, ok := rule.Options["flow"]; ok {
		if !se.matchFlowOptions(flowOpts, flow) {
			return false
		}
	}
	
	// Check content matches
	contentMatched := true
	for option, values := range rule.Options {
		switch option {
		case "content":
			for _, content := range values {
				if !se.matchContent(content, payload, rule.Options) {
					contentMatched = false
					break
				}
			}
		case "pcre":
			for _, pattern := range values {
				if !se.matchPCRE(pattern, payload) {
					return false
				}
			}
		case "dsize":
			for _, size := range values {
				if !se.matchDataSize(size, len(payload)) {
					return false
				}
			}
		case "flags":
			for _, flags := range values {
				if !se.matchTCPFlags(flags, packet) {
					return false
				}
			}
		case "http_header":
			if !se.matchHTTPHeader(values, payload) {
				return false
			}
		case "tls.version":
			if !se.matchTLSVersion(values, payload) {
				return false
			}
		}
	}
	
	return contentMatched
}

func (se *SuricataEngine) matchFlowOptions(flowOpts []string, flow *FlowState) bool {
	if flow == nil {
		return false
	}
	
	for _, opt := range flowOpts {
		parts := strings.Split(opt, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			switch part {
			case "established":
				if flow.State != "established" {
					return false
				}
			case "to_server":
				// Simplified check
				if flow.DstPort >= 1024 && flow.SrcPort < 1024 {
					return false
				}
			case "to_client":
				// Simplified check
				if flow.SrcPort >= 1024 && flow.DstPort < 1024 {
					return false
				}
			case "stateless":
				// Always match for stateless
				continue
			}
		}
	}
	
	return true
}

func (se *SuricataEngine) matchContent(content string, payload []byte, options map[string][]string) bool {
	// Handle hex content
	if strings.Contains(content, "|") {
		content = se.parseHexContent(content)
	}
	
	payloadStr := string(payload)
	
	// Check for nocase option
	if _, nocase := options["nocase"]; nocase {
		return strings.Contains(strings.ToLower(payloadStr), strings.ToLower(content))
	}
	
	// Check depth and offset
	if depthVals, ok := options["depth"]; ok && len(depthVals) > 0 {
		depth, _ := strconv.Atoi(depthVals[0])
		if len(payload) > depth {
			payload = payload[:depth]
		}
	}
	
	if offsetVals, ok := options["offset"]; ok && len(offsetVals) > 0 {
		offset, _ := strconv.Atoi(offsetVals[0])
		if offset < len(payload) {
			payload = payload[offset:]
		}
	}
	
	return strings.Contains(string(payload), content)
}

func (se *SuricataEngine) parseHexContent(content string) string {
	// Simple hex content parser
	re := regexp.MustCompile(`\|([0-9a-fA-F\s]+)\|`)
	return re.ReplaceAllStringFunc(content, func(match string) string {
		hex := strings.Trim(match, "|")
		hex = strings.ReplaceAll(hex, " ", "")
		result := ""
		for i := 0; i < len(hex); i += 2 {
			if i+1 < len(hex) {
				val, _ := strconv.ParseInt(hex[i:i+2], 16, 8)
				result += string(byte(val))
			}
		}
		return result
	})
}

func (se *SuricataEngine) matchPCRE(pattern string, payload []byte) bool {
	// Remove PCRE delimiters and flags
	if len(pattern) >= 2 && pattern[0] == '/' {
		endIdx := strings.LastIndex(pattern[1:], "/")
		if endIdx > 0 {
			pattern = pattern[1:endIdx+1]
		}
	}
	
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	
	return re.Match(payload)
}

func (se *SuricataEngine) matchHTTPHeader(values []string, payload []byte) bool {
	// Simple HTTP header check
	payloadStr := string(payload)
	return strings.Contains(payloadStr, "HTTP/") && strings.Contains(payloadStr, "\r\n")
}

func (se *SuricataEngine) matchTLSVersion(versions []string, payload []byte) bool {
	// Simple TLS version check (would need proper TLS parsing in production)
	if len(payload) < 6 {
		return false
	}
	
	// Check for TLS handshake
	if payload[0] == 0x16 && payload[1] == 0x03 {
		tlsVersion := fmt.Sprintf("%d.%d", payload[1]-2, payload[2])
		for _, v := range versions {
			if v == tlsVersion {
				return true
			}
		}
	}
	
	return false
}

func (se *SuricataEngine) matchDataSize(sizeRule string, actualSize int) bool {
	// Handle operators: >, <, =
	if strings.HasPrefix(sizeRule, ">") {
		threshold, _ := strconv.Atoi(sizeRule[1:])
		return actualSize > threshold
	}
	if strings.HasPrefix(sizeRule, "<") {
		threshold, _ := strconv.Atoi(sizeRule[1:])
		return actualSize < threshold
	}
	
	exactSize, _ := strconv.Atoi(sizeRule)
	return actualSize == exactSize
}

func (se *SuricataEngine) matchTCPFlags(flagsRule string, packet gopacket.Packet) bool {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false
	}
	
	tcp := tcpLayer.(*layers.TCP)
	
	// Parse flag combinations (e.g., "S", "SA", "FPU")
	for _, flag := range flagsRule {
		switch flag {
		case 'S':
			if !tcp.SYN {
				return false
			}
		case 'A':
			if !tcp.ACK {
				return false
			}
		case 'F':
			if !tcp.FIN {
				return false
			}
		case 'R':
			if !tcp.RST {
				return false
			}
		case 'P':
			if !tcp.PSH {
				return false
			}
		case 'U':
			if !tcp.URG {
				return false
			}
		}
	}
	
	return true
}

func (se *SuricataEngine) getPacketPayload(packet gopacket.Packet) []byte {
	if app := packet.ApplicationLayer(); app != nil {
		return app.Payload()
	}
	if transport := packet.TransportLayer(); transport != nil {
		return transport.LayerPayload()
	}
	return nil
}

func (se *SuricataEngine) createAlert(rule SuricataRule, packet gopacket.Packet, flow *FlowState) SuricataAlert {
	netLayer := packet.NetworkLayer()
	srcIP := netLayer.NetworkFlow().Src().String()
	dstIP := netLayer.NetworkFlow().Dst().String()
	
	var srcPort, dstPort int
	var protocol string
	
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		srcPort = int(tcp.SrcPort)
		dstPort = int(tcp.DstPort)
		protocol = "TCP"
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		srcPort = int(udp.SrcPort)
		dstPort = int(udp.DstPort)
		protocol = "UDP"
	} else if packet.Layer(layers.LayerTypeICMPv4) != nil {
		protocol = "ICMP"
	}
	
	alert := SuricataAlert{
		Timestamp: time.Now(),
		EventType: "alert",
		SrcIP:     srcIP,
		SrcPort:   srcPort,
		DstIP:     dstIP,
		DstPort:   dstPort,
		Protocol:  protocol,
		Alert: &AlertInfo{
			Action:      rule.Action,
			GID:         rule.GID,
			SignatureID: rule.SID,
			Rev:         rule.Rev,
			Signature:   rule.Message,
			Category:    rule.Classtype,
			Severity:    se.getSeverity(rule.Priority),
			Metadata:    rule.Metadata,
		},
	}
	
	// Add flow information
	if flow != nil {
		alert.FlowID = flow.ID
		alert.Flow = &FlowInfo{
			PktsToServer:  flow.Packets / 2, // Simplified
			PktsToClient:  flow.Packets / 2,
			BytesToServer: flow.Bytes / 2,
			BytesToClient: flow.Bytes / 2,
			Start:         flow.StartTime.Format(time.RFC3339),
			Duration:      int(time.Since(flow.StartTime).Seconds()),
			State:         flow.State,
		}
	}
	
	// Add packet info
	alert.PacketInfo = &SuricataPacketInfo{
		Linktype:  1, // Ethernet
		Direction: "to_server", // Simplified
	}
	
	return alert
}

func (se *SuricataEngine) getSeverity(priority int) int {
	// Convert priority to severity (1-4 scale)
	switch priority {
	case 1:
		return 1 // Critical
	case 2:
		return 2 // High
	case 3:
		return 3 // Medium
	default:
		return 4 // Low
	}
}

func (se *SuricataEngine) GetAlerts() []SuricataAlert {
	return se.alerts
}

func (se *SuricataEngine) GetAlertsAsJSON() ([]byte, error) {
	if se.eveFormat {
		// EVE JSON format (one JSON object per line)
		var output strings.Builder
		for _, alert := range se.alerts {
			data, err := json.Marshal(alert)
			if err != nil {
				continue
			}
			output.Write(data)
			output.WriteString("\n")
		}
		return []byte(output.String()), nil
	}
	
	// Standard JSON array
	return json.MarshalIndent(se.alerts, "", "  ")
}

func (se *SuricataEngine) GetStats() interface{} {
	return se.stats
}

func (se *SuricataEngine) GetRules() []SuricataRule {
	return se.rules
}

func (se *SuricataEngine) ClearAlerts() {
	se.alerts = make([]SuricataAlert, 0)
}

func (se *SuricataEngine) CleanupFlows() {
	cutoff := time.Now().Add(-5 * time.Minute)
	for id, flow := range se.flowTable {
		if flow.LastActivity.Before(cutoff) {
			delete(se.flowTable, id)
			se.stats.ActiveFlows--
			se.stats.ClosedFlows++
		}
	}
}