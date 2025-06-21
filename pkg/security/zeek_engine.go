package security

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ZeekEngine implements Zeek (formerly Bro) network analysis
type ZeekEngine struct {
	scripts      []ZeekScript
	events       []ZeekEvent
	connections  map[string]*ZeekConnection
	files        map[string]*ZeekFile
	notices      []ZeekNotice
	stats        ZeekStats
	eventHandler *ZeekEventHandler
}

type ZeekScript struct {
	ID          string
	Name        string
	Description string
	Events      []string // Events this script handles
	Code        string   // Simplified script representation
	Enabled     bool
}

type ZeekEvent struct {
	Timestamp   time.Time              `json:"ts"`
	UID         string                 `json:"uid"`
	Type        string                 `json:"event_type"`
	Connection  *ZeekConnection        `json:"conn,omitempty"`
	Details     map[string]interface{} `json:"details"`
}

type ZeekConnection struct {
	TS          time.Time `json:"ts"`
	UID         string    `json:"uid"`
	OrigH       string    `json:"id.orig_h"`
	OrigP       int       `json:"id.orig_p"`
	RespH       string    `json:"id.resp_h"`
	RespP       int       `json:"id.resp_p"`
	Proto       string    `json:"proto"`
	Service     string    `json:"service,omitempty"`
	Duration    float64   `json:"duration,omitempty"`
	OrigBytes   int64     `json:"orig_bytes"`
	RespBytes   int64     `json:"resp_bytes"`
	ConnState   string    `json:"conn_state"`
	LocalOrig   bool      `json:"local_orig"`
	LocalResp   bool      `json:"local_resp"`
	MissedBytes int64     `json:"missed_bytes"`
	History     string    `json:"history"`
	OrigPkts    int       `json:"orig_pkts"`
	RespPkts    int       `json:"resp_pkts"`
	OrigIPBytes int64     `json:"orig_ip_bytes"`
	RespIPBytes int64     `json:"resp_ip_bytes"`
	TunnelParents []string `json:"tunnel_parents,omitempty"`
}

type ZeekFile struct {
	TS            time.Time `json:"ts"`
	FUID          string    `json:"fuid"`
	TxHosts       []string  `json:"tx_hosts"`
	RxHosts       []string  `json:"rx_hosts"`
	ConnUIDs      []string  `json:"conn_uids"`
	Source        string    `json:"source"`
	Depth         int       `json:"depth"`
	Analyzers     []string  `json:"analyzers"`
	MimeType      string    `json:"mime_type,omitempty"`
	Filename      string    `json:"filename,omitempty"`
	Duration      float64   `json:"duration"`
	LocalOrig     bool      `json:"local_orig"`
	IsOrig        bool      `json:"is_orig"`
	SeenBytes     int64     `json:"seen_bytes"`
	TotalBytes    int64     `json:"total_bytes,omitempty"`
	MissingBytes  int64     `json:"missing_bytes"`
	OverflowBytes int64     `json:"overflow_bytes"`
	Timedout      bool      `json:"timedout"`
	MD5           string    `json:"md5,omitempty"`
	SHA1          string    `json:"sha1,omitempty"`
	SHA256        string    `json:"sha256,omitempty"`
	Extracted     string    `json:"extracted,omitempty"`
}

type ZeekNotice struct {
	TS             time.Time              `json:"ts"`
	UID            string                 `json:"uid,omitempty"`
	ID             *ZeekConnID            `json:"id,omitempty"`
	FUID           string                 `json:"fuid,omitempty"`
	MimeType       string                 `json:"mime_type,omitempty"`
	Note           string                 `json:"note"`
	Msg            string                 `json:"msg"`
	Sub            string                 `json:"sub,omitempty"`
	Src            string                 `json:"src,omitempty"`
	Dst            string                 `json:"dst,omitempty"`
	P              int                    `json:"p,omitempty"`
	Actions        []string               `json:"actions"`
	EmailTo        []string               `json:"email_to,omitempty"`
	SuppressFor    float64                `json:"suppress_for,omitempty"`
	Dropped        bool                   `json:"dropped"`
	RemoteLocation map[string]interface{} `json:"remote_location,omitempty"`
}

type ZeekConnID struct {
	OrigH string `json:"orig_h"`
	OrigP int    `json:"orig_p"`
	RespH string `json:"resp_h"`
	RespP int    `json:"resp_p"`
}

type ZeekStats struct {
	TotalPackets     uint64
	TotalConnections uint64
	TotalFiles       uint64
	TotalNotices     uint64
	TotalEvents      uint64
	EventsByType     map[string]uint64
	ServiceStats     map[string]uint64
	ProtocolStats    map[string]uint64
}

type ZeekEventHandler struct {
	handlers map[string]func(*ZeekEngine, gopacket.Packet, *ZeekConnection)
}

func NewZeekEngine() *ZeekEngine {
	engine := &ZeekEngine{
		scripts:     make([]ZeekScript, 0),
		events:      make([]ZeekEvent, 0),
		connections: make(map[string]*ZeekConnection),
		files:       make(map[string]*ZeekFile),
		notices:     make([]ZeekNotice, 0),
		stats: ZeekStats{
			EventsByType:  make(map[string]uint64),
			ServiceStats:  make(map[string]uint64),
			ProtocolStats: make(map[string]uint64),
		},
		eventHandler: &ZeekEventHandler{
			handlers: make(map[string]func(*ZeekEngine, gopacket.Packet, *ZeekConnection)),
		},
	}
	
	engine.loadDefaultScripts()
	engine.registerEventHandlers()
	
	return engine
}

func (ze *ZeekEngine) loadDefaultScripts() {
	// Load default Zeek-style detection scripts
	defaultScripts := []ZeekScript{
		{
			ID:          "scan_detection",
			Name:        "Port Scan Detection",
			Description: "Detects various types of port scanning",
			Events:      []string{"connection_established", "connection_rejected"},
			Code: `
				# Detect port scans
				if (conn$resp_p < 1024 && conn$state == "REJ") {
					local scanner = conn$id$orig_h;
					if (++scan_attempts[scanner] > 20) {
						NOTICE([$note=Port_Scan,
						        $conn=conn,
						        $msg=fmt("%s is scanning ports", scanner)]);
					}
				}
			`,
			Enabled: true,
		},
		{
			ID:          "ssh_bruteforce",
			Name:        "SSH Brute Force Detection",
			Description: "Detects SSH brute force attacks",
			Events:      []string{"ssh_auth_failed", "ssh_auth_successful"},
			Code: `
				# Track failed SSH attempts
				if (event == "ssh_auth_failed") {
					local attacker = conn$id$orig_h;
					if (++ssh_failures[attacker] > 5) {
						NOTICE([$note=SSH_Bruteforce,
						        $conn=conn,
						        $msg=fmt("SSH brute force from %s", attacker)]);
					}
				}
			`,
			Enabled: true,
		},
		{
			ID:          "file_extraction",
			Name:        "File Extraction and Analysis",
			Description: "Extracts and analyzes transferred files",
			Events:      []string{"file_new", "file_over_new_connection", "file_hash"},
			Code: `
				# Extract executable files
				if (f$mime_type in executable_mime_types) {
					Files::add_analyzer(f, Files::ANALYZER_EXTRACT);
					Files::add_analyzer(f, Files::ANALYZER_MD5);
					Files::add_analyzer(f, Files::ANALYZER_SHA256);
				}
			`,
			Enabled: true,
		},
		{
			ID:          "dns_tunneling",
			Name:        "DNS Tunneling Detection",
			Description: "Detects potential DNS tunneling",
			Events:      []string{"dns_request", "dns_response"},
			Code: `
				# Detect suspicious DNS queries
				if (|dns$query| > 50 || dns$query_type == "TXT") {
					if (++dns_suspicious[conn$id$orig_h] > 10) {
						NOTICE([$note=DNS_Tunneling,
						        $msg="Potential DNS tunneling detected"]);
					}
				}
			`,
			Enabled: true,
		},
		{
			ID:          "http_malware",
			Name:        "HTTP Malware Detection",
			Description: "Detects malware behavior over HTTP",
			Events:      []string{"http_request", "http_header", "http_entity_data"},
			Code: `
				# Check for suspicious User-Agents and URLs
				if (http$user_agent in suspicious_agents ||
				    /malware|exploit|shell/ in http$uri) {
					NOTICE([$note=HTTP_Malware,
					        $msg="Suspicious HTTP activity detected"]);
				}
			`,
			Enabled: true,
		},
		{
			ID:          "ssl_anomaly",
			Name:        "SSL/TLS Anomaly Detection",
			Description: "Detects SSL/TLS anomalies and weak configurations",
			Events:      []string{"ssl_established", "ssl_alert", "x509_certificate"},
			Code: `
				# Check for weak SSL/TLS configurations
				if (ssl$version < 0x0303) { # TLS 1.2
					NOTICE([$note=SSL_Weak_Version,
					        $msg="Weak SSL/TLS version detected"]);
				}
			`,
			Enabled: true,
		},
		{
			ID:          "intel_matching",
			Name:        "Threat Intelligence Matching",
			Description: "Matches network traffic against threat intel",
			Events:      []string{"connection_established", "dns_request", "http_request"},
			Code: `
				# Check against threat intelligence
				if (conn$id$resp_h in malicious_ips ||
				    dns$query in malicious_domains) {
					NOTICE([$note=Intel_Hit,
					        $msg="Traffic to known malicious host"]);
				}
			`,
			Enabled: true,
		},
	}
	
	ze.scripts = defaultScripts
}

func (ze *ZeekEngine) registerEventHandlers() {
	// Register event handlers for different packet types
	ze.eventHandler.handlers["new_connection"] = ze.handleNewConnection
	ze.eventHandler.handlers["tcp_packet"] = ze.handleTCPPacket
	ze.eventHandler.handlers["udp_packet"] = ze.handleUDPPacket
	ze.eventHandler.handlers["dns_packet"] = ze.handleDNSPacket
	ze.eventHandler.handlers["http_packet"] = ze.handleHTTPPacket
}

func (ze *ZeekEngine) ProcessPacket(packet gopacket.Packet) []ZeekEvent {
	ze.stats.TotalPackets++
	
	// Get or create connection
	conn := ze.trackConnection(packet)
	if conn == nil {
		return []ZeekEvent{}
	}
	
	var events []ZeekEvent
	
	// Process packet based on type
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if handler, ok := ze.eventHandler.handlers["tcp_packet"]; ok {
			handler(ze, packet, conn)
		}
		// Check for HTTP on standard ports
		tcp := tcpLayer.(*layers.TCP)
		if tcp.DstPort == 80 || tcp.SrcPort == 80 || tcp.DstPort == 8080 || tcp.SrcPort == 8080 {
			if handler, ok := ze.eventHandler.handlers["http_packet"]; ok {
				handler(ze, packet, conn)
			}
		}
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		if handler, ok := ze.eventHandler.handlers["udp_packet"]; ok {
			handler(ze, packet, conn)
		}
	}
	
	// Process application layer
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		if handler, ok := ze.eventHandler.handlers["dns_packet"]; ok {
			handler(ze, packet, conn)
		}
	}
	
	// Check for security events
	ze.runSecurityAnalysis(conn, packet)
	
	// Get recent events
	for i := len(ze.events) - 5; i < len(ze.events); i++ {
		if i >= 0 {
			events = append(events, ze.events[i])
		}
	}
	
	return events
}

func (ze *ZeekEngine) trackConnection(packet gopacket.Packet) *ZeekConnection {
	connID := ze.getConnectionID(packet)
	if connID == "" {
		return nil
	}
	
	conn, exists := ze.connections[connID]
	if !exists {
		conn = ze.createNewConnection(packet)
		if conn != nil {
			ze.connections[connID] = conn
			ze.stats.TotalConnections++
			
			// Fire new_connection event
			ze.fireEvent("new_connection", conn, nil)
		}
	}
	
	if conn != nil {
		// Update connection stats
		ze.updateConnectionStats(conn, packet)
	}
	
	return conn
}

func (ze *ZeekEngine) getConnectionID(packet gopacket.Packet) string {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return ""
	}
	
	src := netLayer.NetworkFlow().Src().String()
	dst := netLayer.NetworkFlow().Dst().String()
	
	var srcPort, dstPort int
	// var proto string
	
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		srcPort = int(tcp.SrcPort)
		dstPort = int(tcp.DstPort)
		// proto = "tcp"
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		srcPort = int(udp.SrcPort)
		dstPort = int(udp.DstPort)
		// proto = "udp"
	}
	// else: proto = "other" - no additional processing needed
	
	// Create Zeek-style UID
	return fmt.Sprintf("C%s%d%s%d", 
		strings.ReplaceAll(src, ".", ""),
		srcPort,
		strings.ReplaceAll(dst, ".", ""),
		dstPort)
}

func (ze *ZeekEngine) createNewConnection(packet gopacket.Packet) *ZeekConnection {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return nil
	}
	
	conn := &ZeekConnection{
		TS:    time.Now(),
		UID:   ze.getConnectionID(packet),
		OrigH: netLayer.NetworkFlow().Src().String(),
		RespH: netLayer.NetworkFlow().Dst().String(),
		LocalOrig: ze.isLocalIP(netLayer.NetworkFlow().Src().String()),
		LocalResp: ze.isLocalIP(netLayer.NetworkFlow().Dst().String()),
	}
	
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		conn.OrigP = int(tcp.SrcPort)
		conn.RespP = int(tcp.DstPort)
		conn.Proto = "tcp"
		conn.Service = ze.identifyService(int(tcp.DstPort), "tcp")
		
		// Set initial connection state
		if tcp.SYN && !tcp.ACK {
			conn.ConnState = "S0"
		} else if tcp.SYN && tcp.ACK {
			conn.ConnState = "S1"
		}
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		conn.OrigP = int(udp.SrcPort)
		conn.RespP = int(udp.DstPort)
		conn.Proto = "udp"
		conn.Service = ze.identifyService(int(udp.DstPort), "udp")
		conn.ConnState = "SF" // Simplified for UDP
	}
	
	ze.stats.ProtocolStats[conn.Proto]++
	if conn.Service != "" {
		ze.stats.ServiceStats[conn.Service]++
	}
	
	return conn
}

func (ze *ZeekEngine) updateConnectionStats(conn *ZeekConnection, packet gopacket.Packet) {
	// Update packet counts
	netLayer := packet.NetworkLayer()
	if netLayer.NetworkFlow().Src().String() == conn.OrigH {
		conn.OrigPkts++
		conn.OrigIPBytes += int64(len(packet.Data()))
		if payload := ze.getPayload(packet); payload != nil {
			conn.OrigBytes += int64(len(payload))
		}
	} else {
		conn.RespPkts++
		conn.RespIPBytes += int64(len(packet.Data()))
		if payload := ze.getPayload(packet); payload != nil {
			conn.RespBytes += int64(len(payload))
		}
	}
	
	// Update connection state for TCP
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		ze.updateTCPState(conn, tcp)
		
		// Update history string (simplified)
		if tcp.SYN {
			conn.History += "S"
		}
		if tcp.ACK {
			conn.History += "A"
		}
		if tcp.FIN {
			conn.History += "F"
		}
		if tcp.RST {
			conn.History += "R"
		}
	}
	
	// Update duration
	conn.Duration = time.Since(conn.TS).Seconds()
}

func (ze *ZeekEngine) updateTCPState(conn *ZeekConnection, tcp *layers.TCP) {
	// Simplified TCP state tracking
	switch conn.ConnState {
	case "S0":
		if tcp.SYN && tcp.ACK {
			conn.ConnState = "S1"
		}
	case "S1":
		if tcp.ACK && !tcp.SYN {
			conn.ConnState = "SF"
		}
	case "SF":
		if tcp.FIN {
			conn.ConnState = "S2"
		} else if tcp.RST {
			conn.ConnState = "REJ"
		}
	}
}

func (ze *ZeekEngine) identifyService(port int, proto string) string {
	// Common service identification
	if proto == "tcp" {
		switch port {
		case 21:
			return "ftp"
		case 22:
			return "ssh"
		case 23:
			return "telnet"
		case 25:
			return "smtp"
		case 80:
			return "http"
		case 110:
			return "pop3"
		case 143:
			return "imap"
		case 443:
			return "ssl"
		case 445:
			return "smb"
		case 3389:
			return "rdp"
		}
	} else if proto == "udp" {
		switch port {
		case 53:
			return "dns"
		case 67, 68:
			return "dhcp"
		case 69:
			return "tftp"
		case 123:
			return "ntp"
		case 161:
			return "snmp"
		}
	}
	return ""
}

func (ze *ZeekEngine) isLocalIP(ip string) bool {
	// Check if IP is in local network ranges
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

func (ze *ZeekEngine) getPayload(packet gopacket.Packet) []byte {
	if app := packet.ApplicationLayer(); app != nil {
		return app.Payload()
	}
	if transport := packet.TransportLayer(); transport != nil {
		return transport.LayerPayload()
	}
	return nil
}

func (ze *ZeekEngine) fireEvent(eventType string, conn *ZeekConnection, details map[string]interface{}) {
	event := ZeekEvent{
		Timestamp:  time.Now(),
		UID:        conn.UID,
		Type:       eventType,
		Connection: conn,
		Details:    details,
	}
	
	ze.events = append(ze.events, event)
	ze.stats.TotalEvents++
	ze.stats.EventsByType[eventType]++
	
	// Keep only recent events
	if len(ze.events) > 10000 {
		ze.events = ze.events[len(ze.events)-10000:]
	}
}

// Event handlers

func (ze *ZeekEngine) handleNewConnection(engine *ZeekEngine, packet gopacket.Packet, conn *ZeekConnection) {
	// Check against scripts for new connection events
	for _, script := range engine.scripts {
		if !script.Enabled {
			continue
		}
		
		for _, event := range script.Events {
			if event == "connection_established" {
				// Run script logic (simplified)
				engine.executeScript(script, conn, packet)
			}
		}
	}
}

func (ze *ZeekEngine) handleTCPPacket(engine *ZeekEngine, packet gopacket.Packet, conn *ZeekConnection) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	
	tcp := tcpLayer.(*layers.TCP)
	
	// Detect port scanning
	if tcp.SYN && !tcp.ACK && conn.ConnState == "S0" {
		engine.checkPortScan(conn)
	}
	
	// Detect service-specific events
	switch conn.Service {
	case "ssh":
		engine.analyzeSSH(packet, conn)
	case "http":
		engine.analyzeHTTP(packet, conn)
	case "ssl":
		engine.analyzeSSL(packet, conn)
	}
}

func (ze *ZeekEngine) handleUDPPacket(engine *ZeekEngine, packet gopacket.Packet, conn *ZeekConnection) {
	// Handle UDP-specific protocols
	switch conn.Service {
	case "dns":
		engine.analyzeDNS(packet, conn)
	case "dhcp":
		engine.analyzeDHCP(packet, conn)
	}
}

func (ze *ZeekEngine) handleDNSPacket(engine *ZeekEngine, packet gopacket.Packet, conn *ZeekConnection) {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}
	
	dns := dnsLayer.(*layers.DNS)
	
	// Process DNS queries
	for _, q := range dns.Questions {
		details := map[string]interface{}{
			"query":      string(q.Name),
			"query_type": q.Type.String(),
			"query_class": q.Class.String(),
		}
		
		engine.fireEvent("dns_request", conn, details)
		
		// Check for DNS tunneling
		if len(q.Name) > 50 || q.Type == layers.DNSTypeTXT {
			engine.createNotice("DNS_Tunneling", "Suspicious DNS query detected", conn)
		}
	}
}

func (ze *ZeekEngine) handleHTTPPacket(engine *ZeekEngine, packet gopacket.Packet, conn *ZeekConnection) {
	payload := engine.getPayload(packet)
	if payload == nil {
		return
	}
	
	payloadStr := string(payload)
	
	// Simple HTTP request detection
	if strings.HasPrefix(payloadStr, "GET ") || 
	   strings.HasPrefix(payloadStr, "POST ") ||
	   strings.HasPrefix(payloadStr, "PUT ") {
		lines := strings.Split(payloadStr, "\r\n")
		if len(lines) > 0 {
			requestLine := lines[0]
			parts := strings.Fields(requestLine)
			
			if len(parts) >= 3 {
				details := map[string]interface{}{
					"method":  parts[0],
					"uri":     parts[1],
					"version": parts[2],
				}
				
				// Extract headers
				headers := make(map[string]string)
				for i := 1; i < len(lines); i++ {
					if lines[i] == "" {
						break
					}
					headerParts := strings.SplitN(lines[i], ":", 2)
					if len(headerParts) == 2 {
						headers[strings.TrimSpace(headerParts[0])] = strings.TrimSpace(headerParts[1])
					}
				}
				details["headers"] = headers
				
				engine.fireEvent("http_request", conn, details)
				
				// Check for suspicious patterns
				if userAgent, ok := headers["User-Agent"]; ok {
					if strings.Contains(strings.ToLower(userAgent), "bot") ||
					   strings.Contains(strings.ToLower(userAgent), "scanner") {
						engine.createNotice("HTTP_Suspicious_UA", "Suspicious User-Agent detected", conn)
					}
				}
			}
		}
	}
}

// Analysis functions

func (ze *ZeekEngine) checkPortScan(conn *ZeekConnection) {
	// Simple port scan detection
	scanner := conn.OrigH
	
	// Count connections from this source
	scanCount := 0
	for _, c := range ze.connections {
		if c.OrigH == scanner && c.ConnState == "S0" {
			scanCount++
		}
	}
	
	if scanCount > 20 {
		ze.createNotice("Port_Scan", 
			fmt.Sprintf("%s is scanning ports (count: %d)", scanner, scanCount), 
			conn)
	}
}

func (ze *ZeekEngine) analyzeSSH(packet gopacket.Packet, conn *ZeekConnection) {
	payload := ze.getPayload(packet)
	if payload == nil {
		return
	}
	
	payloadStr := string(payload)
	
	// Check for SSH version
	if strings.HasPrefix(payloadStr, "SSH-") {
		details := map[string]interface{}{
			"version": strings.TrimSpace(payloadStr),
		}
		ze.fireEvent("ssh_server_version", conn, details)
	}
	
	// Simple brute force detection (would need more sophisticated analysis)
	if conn.OrigPkts > 10 && conn.Duration < 5.0 {
		ze.createNotice("SSH_Bruteforce", 
			fmt.Sprintf("Potential SSH brute force from %s", conn.OrigH), 
			conn)
	}
}

func (ze *ZeekEngine) analyzeDNS(packet gopacket.Packet, conn *ZeekConnection) {
	// Handled in handleDNSPacket
}

func (ze *ZeekEngine) analyzeDHCP(packet gopacket.Packet, conn *ZeekConnection) {
	// DHCP analysis would go here
}

func (ze *ZeekEngine) analyzeHTTP(packet gopacket.Packet, conn *ZeekConnection) {
	// Handled in handleHTTPPacket
}

func (ze *ZeekEngine) analyzeSSL(packet gopacket.Packet, conn *ZeekConnection) {
	payload := ze.getPayload(packet)
	if len(payload) < 6 {
		return
	}
	
	// Check for TLS handshake
	if payload[0] == 0x16 { // Handshake
		version := fmt.Sprintf("%d.%d", payload[1], payload[2])
		
		details := map[string]interface{}{
			"version": version,
		}
		
		ze.fireEvent("ssl_established", conn, details)
		
		// Check for weak SSL/TLS versions
		if payload[1] == 0x03 && payload[2] < 0x03 { // Less than TLS 1.2
			ze.createNotice("SSL_Weak_Version",
				fmt.Sprintf("Weak SSL/TLS version %s detected", version),
				conn)
		}
	}
}

func (ze *ZeekEngine) runSecurityAnalysis(conn *ZeekConnection, packet gopacket.Packet) {
	// Run enabled scripts
	for _, script := range ze.scripts {
		if !script.Enabled {
			continue
		}
		
		ze.executeScript(script, conn, packet)
	}
}

func (ze *ZeekEngine) executeScript(script ZeekScript, conn *ZeekConnection, packet gopacket.Packet) {
	// Simplified script execution
	// In a real implementation, this would use a proper scripting engine
	
	switch script.ID {
	case "scan_detection":
		if conn.ConnState == "REJ" && conn.RespP < 1024 {
			ze.checkPortScan(conn)
		}
		
	case "ssh_bruteforce":
		if conn.Service == "ssh" && conn.OrigPkts > 10 && conn.Duration < 5.0 {
			ze.createNotice("SSH_Bruteforce",
				fmt.Sprintf("SSH brute force from %s", conn.OrigH),
				conn)
		}
		
	case "dns_tunneling":
		// Handled in DNS packet handler
		
	case "intel_matching":
		// Check against threat intelligence (simplified)
		maliciousIPs := []string{"10.0.0.1", "192.168.100.100"} // Example
		for _, ip := range maliciousIPs {
			if conn.OrigH == ip || conn.RespH == ip {
				ze.createNotice("Intel_Hit",
					fmt.Sprintf("Traffic to/from known malicious IP: %s", ip),
					conn)
			}
		}
	}
}

func (ze *ZeekEngine) createNotice(note, msg string, conn *ZeekConnection) {
	notice := ZeekNotice{
		TS:   time.Now(),
		UID:  conn.UID,
		Note: note,
		Msg:  msg,
		ID: &ZeekConnID{
			OrigH: conn.OrigH,
			OrigP: conn.OrigP,
			RespH: conn.RespH,
			RespP: conn.RespP,
		},
		Actions: []string{"Notice::ACTION_LOG"},
	}
	
	ze.notices = append(ze.notices, notice)
	ze.stats.TotalNotices++
	
	// Also create an event
	ze.fireEvent("notice", conn, map[string]interface{}{
		"note": note,
		"msg":  msg,
	})
}

// File tracking

func (ze *ZeekEngine) trackFile(fuid string, source string, conn *ZeekConnection) *ZeekFile {
	file := &ZeekFile{
		TS:       time.Now(),
		FUID:     fuid,
		Source:   source,
		ConnUIDs: []string{conn.UID},
		TxHosts:  []string{conn.OrigH},
		RxHosts:  []string{conn.RespH},
	}
	
	ze.files[fuid] = file
	ze.stats.TotalFiles++
	
	return file
}

// Getters

func (ze *ZeekEngine) GetConnections() []ZeekConnection {
	conns := make([]ZeekConnection, 0, len(ze.connections))
	for _, conn := range ze.connections {
		conns = append(conns, *conn)
	}
	return conns
}

func (ze *ZeekEngine) GetFiles() []ZeekFile {
	files := make([]ZeekFile, 0, len(ze.files))
	for _, file := range ze.files {
		files = append(files, *file)
	}
	return files
}

func (ze *ZeekEngine) GetNotices() []ZeekNotice {
	return ze.notices
}

func (ze *ZeekEngine) GetEvents() []ZeekEvent {
	return ze.events
}

func (ze *ZeekEngine) GetStats() interface{} {
	return ze.stats
}

func (ze *ZeekEngine) ClearAlerts() {
	ze.events = make([]ZeekEvent, 0)
	ze.notices = make([]ZeekNotice, 0)
}

func (ze *ZeekEngine) GetScripts() []ZeekScript {
	return ze.scripts
}

// Cleanup

func (ze *ZeekEngine) CleanupOldConnections() {
	cutoff := time.Now().Add(-5 * time.Minute)
	
	for id, conn := range ze.connections {
		if conn.TS.Before(cutoff) {
			delete(ze.connections, id)
		}
	}
}

func (ze *ZeekEngine) ClearEvents() {
	ze.events = make([]ZeekEvent, 0)
}

func (ze *ZeekEngine) ClearNotices() {
	ze.notices = make([]ZeekNotice, 0)
}