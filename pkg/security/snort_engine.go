package security

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type SnortEngine struct {
	rules         []SnortRule
	rulesByAction map[string][]SnortRule
	alerts        []SnortAlert
	stats         SnortStats
}

type SnortRule struct {
	ID          int
	Action      string // alert, log, pass, drop, reject
	Protocol    string // tcp, udp, icmp, ip
	SrcIP       string
	SrcPort     string
	Direction   string // -> or <>
	DstIP       string
	DstPort     string
	Options     map[string]string
	Message     string
	Classtype   string
	Priority    int
	SID         int
	Rev         int
	Raw         string
}

type SnortAlert struct {
	Timestamp   time.Time
	RuleID      int
	SID         int
	Message     string
	Protocol    string
	SrcIP       string
	SrcPort     int
	DstIP       string
	DstPort     int
	Priority    int
	Classtype   string
	PacketData  []byte
	Details     map[string]interface{}
}

type SnortStats struct {
	TotalPackets   uint64
	TotalAlerts    uint64
	AlertsByRule   map[int]uint64
	AlertsByType   map[string]uint64
	LastAlert      time.Time
}

func NewSnortEngine() *SnortEngine {
	engine := &SnortEngine{
		rules:         make([]SnortRule, 0),
		rulesByAction: make(map[string][]SnortRule),
		alerts:        make([]SnortAlert, 0),
		stats: SnortStats{
			AlertsByRule: make(map[int]uint64),
			AlertsByType: make(map[string]uint64),
		},
	}
	
	// Load default rules
	engine.loadDefaultRules()
	
	return engine
}

func (se *SnortEngine) loadDefaultRules() {
	defaultRules := []string{
		// Malware and exploits
		`alert tcp any any -> any any (msg:"MALWARE Generic backdoor command"; content:"sh"; content:"rm -rf"; sid:1000001; classtype:trojan-activity; priority:1;)`,
		`alert tcp any any -> any any (msg:"EXPLOIT SQL injection attempt"; content:"union select"; nocase; sid:1000002; classtype:web-application-attack; priority:2;)`,
		`alert tcp any any -> any any (msg:"EXPLOIT XSS attempt"; content:"<script>"; nocase; sid:1000003; classtype:web-application-attack; priority:2;)`,
		
		// Port scanning and reconnaissance
		`alert tcp any any -> any any (msg:"SCAN Port scan detected"; flags:S; threshold:type both, track by_src, count 20, seconds 60; sid:1000004; classtype:attempted-recon; priority:3;)`,
		`alert icmp any any -> any any (msg:"SCAN ICMP ping sweep"; itype:8; threshold:type both, track by_src, count 10, seconds 60; sid:1000005; classtype:attempted-recon; priority:3;)`,
		
		// Brute force attacks
		`alert tcp any any -> any 22 (msg:"ATTACK SSH brute force attempt"; content:"SSH"; threshold:type both, track by_src, count 5, seconds 60; sid:1000006; classtype:attempted-user; priority:2;)`,
		`alert tcp any any -> any 21 (msg:"ATTACK FTP brute force attempt"; content:"530"; threshold:type both, track by_src, count 5, seconds 60; sid:1000007; classtype:attempted-user; priority:2;)`,
		`alert tcp any any -> any 3389 (msg:"ATTACK RDP brute force attempt"; threshold:type both, track by_src, count 5, seconds 300; sid:1000008; classtype:attempted-user; priority:2;)`,
		
		// Suspicious network activity
		`alert tcp any any -> any any (msg:"SUSPICIOUS Large file transfer"; dsize:>1000000; sid:1000009; classtype:policy-violation; priority:3;)`,
		`alert udp any any -> any 53 (msg:"SUSPICIOUS DNS tunneling"; dsize:>512; sid:1000010; classtype:policy-violation; priority:3;)`,
		`alert tcp any any -> any any (msg:"SUSPICIOUS Base64 encoded data"; content:"base64"; nocase; sid:1000011; classtype:policy-violation; priority:3;)`,
		
		// Protocol-specific attacks
		`alert tcp any any -> any 80 (msg:"WEB-ATTACKS Directory traversal"; content:"../"; sid:1000012; classtype:web-application-attack; priority:2;)`,
		`alert tcp any any -> any 443 (msg:"SSL Certificate anomaly"; content:"certificate"; sid:1000013; classtype:protocol-command-decode; priority:3;)`,
		`alert tcp any any -> any 25 (msg:"SMTP Command injection"; content:"RCPT TO:"; content:"|"; sid:1000014; classtype:attempted-user; priority:2;)`,
		
		// Data exfiltration
		`alert tcp any any -> any any (msg:"POLICY Data exfiltration via HTTP POST"; content:"POST"; content:"password"; sid:1000015; classtype:policy-violation; priority:2;)`,
		`alert tcp any any -> any any (msg:"POLICY Sensitive file access"; content:".key"; content:".pem"; sid:1000016; classtype:policy-violation; priority:2;)`,
		
		// Botnet and C2 communication
		`alert tcp any any -> any any (msg:"MALWARE Botnet beacon"; content:"bot"; content:"cmd"; sid:1000017; classtype:trojan-activity; priority:1;)`,
		`alert tcp any any -> any any (msg:"MALWARE IRC bot communication"; content:"PRIVMSG"; content:"!"; sid:1000018; classtype:trojan-activity; priority:1;)`,
	}
	
	for _, ruleStr := range defaultRules {
		if rule := se.parseRule(ruleStr); rule != nil {
			se.AddRule(*rule)
		}
	}
}

func (se *SnortEngine) parseRule(ruleStr string) *SnortRule {
	// Parse Snort rule format: action protocol src_ip src_port direction dst_ip dst_port (options)
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
	
	rule := &SnortRule{
		Action:    headerParts[0],
		Protocol:  headerParts[1],
		SrcIP:     headerParts[2],
		SrcPort:   headerParts[3],
		Direction: headerParts[4],
		DstIP:     headerParts[5],
		DstPort:   headerParts[6],
		Options:   make(map[string]string),
		Raw:       ruleStr,
	}
	
	// Parse options
	se.parseOptions(rule, optionsStr)
	
	return rule
}

func (se *SnortEngine) parseOptions(rule *SnortRule, optionsStr string) {
	// Split options by semicolon, but handle quoted strings
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
			rule.Options[key] = value
			
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
			}
		} else {
			// Standalone options (like nocase, flags)
			rule.Options[option] = ""
		}
	}
}

func (se *SnortEngine) splitOptions(optionsStr string) []string {
	var options []string
	var current strings.Builder
	inQuotes := false
	
	for _, char := range optionsStr {
		switch char {
		case '"':
			inQuotes = !inQuotes
			current.WriteRune(char)
		case ';':
			if !inQuotes {
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

func (se *SnortEngine) AddRule(rule SnortRule) {
	rule.ID = len(se.rules)
	se.rules = append(se.rules, rule)
	se.rulesByAction[rule.Action] = append(se.rulesByAction[rule.Action], rule)
}

func (se *SnortEngine) LoadRulesFromFile(filename string) error {
	// Implementation would read rules from file
	return fmt.Errorf("file loading not implemented")
}

func (se *SnortEngine) ProcessPacket(packet gopacket.Packet) []SnortAlert {
	se.stats.TotalPackets++
	
	var alerts []SnortAlert
	
	for _, rule := range se.rules {
		if se.matchRule(rule, packet) {
			alert := se.createAlert(rule, packet)
			alerts = append(alerts, alert)
			se.alerts = append(se.alerts, alert)
			
			se.stats.TotalAlerts++
			se.stats.AlertsByRule[rule.ID]++
			se.stats.AlertsByType[rule.Classtype]++
			se.stats.LastAlert = time.Now()
		}
	}
	
	return alerts
}

func (se *SnortEngine) matchRule(rule SnortRule, packet gopacket.Packet) bool {
	// Check protocol
	if !se.matchProtocol(rule.Protocol, packet) {
		return false
	}
	
	// Check IP addresses and ports
	if !se.matchNetwork(rule, packet) {
		return false
	}
	
	// Check content and other options
	return se.matchOptions(rule, packet)
}

func (se *SnortEngine) matchProtocol(protocol string, packet gopacket.Packet) bool {
	switch strings.ToLower(protocol) {
	case "tcp":
		return packet.Layer(layers.LayerTypeTCP) != nil
	case "udp":
		return packet.Layer(layers.LayerTypeUDP) != nil
	case "icmp":
		return packet.Layer(layers.LayerTypeICMPv4) != nil
	case "ip":
		return packet.NetworkLayer() != nil
	default:
		return true // "any"
	}
}

func (se *SnortEngine) matchNetwork(rule SnortRule, packet gopacket.Packet) bool {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return false
	}
	
	srcIP := netLayer.NetworkFlow().Src().String()
	dstIP := netLayer.NetworkFlow().Dst().String()
	
	var srcPort, dstPort int
	
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		srcPort = int(tcp.SrcPort)
		dstPort = int(tcp.DstPort)
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		srcPort = int(udp.SrcPort)
		dstPort = int(udp.DstPort)
	}
	
	// Match source
	if !se.matchIPAddress(rule.SrcIP, srcIP) {
		return false
	}
	if !se.matchPort(rule.SrcPort, srcPort) {
		return false
	}
	
	// Match destination
	if !se.matchIPAddress(rule.DstIP, dstIP) {
		return false
	}
	if !se.matchPort(rule.DstPort, dstPort) {
		return false
	}
	
	return true
}

func (se *SnortEngine) matchIPAddress(ruleIP, packetIP string) bool {
	if ruleIP == "any" {
		return true
	}
	
	// Handle CIDR notation
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

func (se *SnortEngine) matchPort(rulePort string, packetPort int) bool {
	if rulePort == "any" {
		return true
	}
	
	// Handle port ranges
	if strings.Contains(rulePort, ":") {
		parts := strings.Split(rulePort, ":")
		if len(parts) == 2 {
			start, _ := strconv.Atoi(parts[0])
			end, _ := strconv.Atoi(parts[1])
			return packetPort >= start && packetPort <= end
		}
	}
	
	port, err := strconv.Atoi(rulePort)
	if err != nil {
		return false
	}
	
	return port == packetPort
}

func (se *SnortEngine) matchOptions(rule SnortRule, packet gopacket.Packet) bool {
	payload := se.getPacketPayload(packet)
	
	for option, value := range rule.Options {
		switch option {
		case "content":
			if !se.matchContent(value, payload, rule.Options) {
				return false
			}
		case "dsize":
			if !se.matchDataSize(value, len(payload)) {
				return false
			}
		case "flags":
			if !se.matchTCPFlags(value, packet) {
				return false
			}
		case "itype":
			if !se.matchICMPType(value, packet) {
				return false
			}
		}
	}
	
	return true
}

func (se *SnortEngine) matchContent(content string, payload []byte, options map[string]string) bool {
	payloadStr := string(payload)
	
	// Check for nocase option
	if _, nocase := options["nocase"]; nocase {
		return strings.Contains(strings.ToLower(payloadStr), strings.ToLower(content))
	}
	
	return strings.Contains(payloadStr, content)
}

func (se *SnortEngine) matchDataSize(sizeRule string, actualSize int) bool {
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

func (se *SnortEngine) matchTCPFlags(flagsRule string, packet gopacket.Packet) bool {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false
	}
	
	tcp := tcpLayer.(*layers.TCP)
	
	// Simple flag matching (S for SYN, A for ACK, etc.)
	switch flagsRule {
	case "S":
		return tcp.SYN
	case "A":
		return tcp.ACK
	case "F":
		return tcp.FIN
	case "R":
		return tcp.RST
	case "P":
		return tcp.PSH
	case "U":
		return tcp.URG
	}
	
	return false
}

func (se *SnortEngine) matchICMPType(typeRule string, packet gopacket.Packet) bool {
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	if icmpLayer == nil {
		return false
	}
	
	icmp := icmpLayer.(*layers.ICMPv4)
	expectedType, _ := strconv.Atoi(typeRule)
	
	return int(icmp.TypeCode.Type()) == expectedType
}

func (se *SnortEngine) getPacketPayload(packet gopacket.Packet) []byte {
	if app := packet.ApplicationLayer(); app != nil {
		return app.Payload()
	}
	if transport := packet.TransportLayer(); transport != nil {
		return transport.LayerPayload()
	}
	return nil
}

func (se *SnortEngine) createAlert(rule SnortRule, packet gopacket.Packet) SnortAlert {
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
	
	return SnortAlert{
		Timestamp:  time.Now(),
		RuleID:     rule.ID,
		SID:        rule.SID,
		Message:    rule.Message,
		Protocol:   protocol,
		SrcIP:      srcIP,
		SrcPort:    srcPort,
		DstIP:      dstIP,
		DstPort:    dstPort,
		Priority:   rule.Priority,
		Classtype:  rule.Classtype,
		PacketData: se.getPacketPayload(packet),
		Details: map[string]interface{}{
			"rule_action": rule.Action,
			"packet_size": len(se.getPacketPayload(packet)),
		},
	}
}

func (se *SnortEngine) GetAlerts() []SnortAlert {
	return se.alerts
}

func (se *SnortEngine) GetStats() interface{} {
	return se.stats
}

func (se *SnortEngine) GetRules() []SnortRule {
	return se.rules
}

func (se *SnortEngine) ClearAlerts() {
	se.alerts = make([]SnortAlert, 0)
}

func (se *SnortEngine) GetRecentAlerts(duration time.Duration) []SnortAlert {
	cutoff := time.Now().Add(-duration)
	var recent []SnortAlert
	
	for _, alert := range se.alerts {
		if alert.Timestamp.After(cutoff) {
			recent = append(recent, alert)
		}
	}
	
	return recent
}