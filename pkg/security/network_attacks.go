package security

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// NetworkAttackDetector detects various network-based attacks
type NetworkAttackDetector struct {
	// MAC tracking
	ipMacMap      map[string]MACEntry
	macChangeLog  []MACChangeEvent
	
	// ARP tracking
	arpTable      map[string]ARPEntry
	arpRequests   map[string][]time.Time
	
	// DHCP tracking
	dhcpServers   map[string]DHCPServer
	dhcpRequests  map[string][]time.Time
	dhcpLeases    map[string]DHCPLease
	
	// DNS tracking
	dnsServers    map[string]DNSServer
	dnsQueries    map[string][]DNSQuery
	dnsResponses  map[string][]DNSResponse
	
	// WiFi tracking
	wifiClients   map[string]WiFiClient
	deauthPackets []DeauthEvent
	beacons       map[string][]BeaconFrame
	
	// VLAN tracking
	vlanTraffic   map[uint16]VLANStats
	
	// Statistics
	stats         AttackStats
	alerts        []AttackAlert
	
	mu            sync.RWMutex
}

// Attack detection structures

type MACEntry struct {
	IP           string
	MAC          string
	FirstSeen    time.Time
	LastSeen     time.Time
	PacketCount  int
	Vendor       string
}

type MACChangeEvent struct {
	Timestamp    time.Time
	IP           string
	OldMAC       string
	NewMAC       string
	Suspicious   bool
}

type ARPEntry struct {
	IP           string
	MAC          string
	Interface    string
	LastUpdated  time.Time
	IsGratuitous bool
}

type DHCPServer struct {
	IP           string
	MAC          string
	FirstSeen    time.Time
	LastSeen     time.Time
	OffersCount  int
	Legitimate   bool
}

type DHCPLease struct {
	ClientMAC    string
	ClientIP     string
	ServerIP     string
	LeaseTime    time.Duration
	Timestamp    time.Time
}

type DNSServer struct {
	IP           string
	FirstSeen    time.Time
	LastSeen     time.Time
	ResponseCount int
	Legitimate   bool
}

type DNSQuery struct {
	Timestamp    time.Time
	QueryID      uint16
	ClientIP     string
	ServerIP     string
	QueryName    string
	QueryType    string
}

type DNSResponse struct {
	Timestamp    time.Time
	QueryID      uint16
	ServerIP     string
	ClientIP     string
	Answers      []string
	Suspicious   bool
}

type WiFiClient struct {
	MAC          string
	SSID         string
	Channel      int
	SignalStrength int
	FirstSeen    time.Time
	LastSeen     time.Time
	ProbeRequests []string
}

type DeauthEvent struct {
	Timestamp    time.Time
	SourceMAC    string
	DestMAC      string
	BSSID        string
	Reason       uint16
}

type BeaconFrame struct {
	Timestamp    time.Time
	BSSID        string
	SSID         string
	Channel      int
	Encryption   string
}

type VLANStats struct {
	ID           uint16
	PacketCount  int
	ByteCount    int64
	FirstSeen    time.Time
	LastSeen     time.Time
	DoubleTagged bool
}

type AttackStats struct {
	TotalPackets      uint64
	MacSpoofing       uint64
	ArpSpoofing       uint64
	DhcpAttacks       uint64
	DnsHijacking      uint64
	WiFiAttacks       uint64
	VlanAttacks       uint64
	MonitorMode       uint64
}

type AttackAlert struct {
	Timestamp    time.Time
	Type         string
	Severity     string
	Description  string
	SourceIP     string
	SourceMAC    string
	DestIP       string
	DestMAC      string
	Details      map[string]interface{}
}

func NewNetworkAttackDetector() *NetworkAttackDetector {
	return &NetworkAttackDetector{
		ipMacMap:      make(map[string]MACEntry),
		macChangeLog:  make([]MACChangeEvent, 0),
		arpTable:      make(map[string]ARPEntry),
		arpRequests:   make(map[string][]time.Time),
		dhcpServers:   make(map[string]DHCPServer),
		dhcpRequests:  make(map[string][]time.Time),
		dhcpLeases:    make(map[string]DHCPLease),
		dnsServers:    make(map[string]DNSServer),
		dnsQueries:    make(map[string][]DNSQuery),
		dnsResponses:  make(map[string][]DNSResponse),
		wifiClients:   make(map[string]WiFiClient),
		deauthPackets: make([]DeauthEvent, 0),
		beacons:       make(map[string][]BeaconFrame),
		vlanTraffic:   make(map[uint16]VLANStats),
		alerts:        make([]AttackAlert, 0),
	}
}

func (nad *NetworkAttackDetector) ProcessPacket(packet gopacket.Packet) []AttackAlert {
	nad.mu.Lock()
	defer nad.mu.Unlock()
	
	nad.stats.TotalPackets++
	var alerts []AttackAlert
	
	// Layer 2 analysis
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		
		// Check for monitor mode indicators
		if nad.detectMonitorMode(packet) {
			alert := nad.createAlert("monitor_mode", "high", 
				"Monitor mode detected - possible wireless sniffing",
				"", eth.SrcMAC.String(), "", eth.DstMAC.String(),
				map[string]interface{}{"interface": "unknown"})
			alerts = append(alerts, alert)
			nad.stats.MonitorMode++
		}
		
		// VLAN analysis
		if vlanLayer := packet.Layer(layers.LayerTypeDot1Q); vlanLayer != nil {
			vlan := vlanLayer.(*layers.Dot1Q)
			nad.analyzeVLAN(vlan, packet)
		}
	}
	
	// ARP analysis
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp := arpLayer.(*layers.ARP)
		if arpAlerts := nad.analyzeARP(arp, packet); len(arpAlerts) > 0 {
			alerts = append(alerts, arpAlerts...)
		}
	}
	
	// IP layer analysis for MAC tracking
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
			eth := ethLayer.(*layers.Ethernet)
			srcIP := netLayer.NetworkFlow().Src().String()
			
			// Track IP-MAC mappings
			if macAlerts := nad.trackIPMAC(srcIP, eth.SrcMAC.String()); len(macAlerts) > 0 {
				alerts = append(alerts, macAlerts...)
			}
		}
	}
	
	// DHCP analysis
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		if udp.SrcPort == 67 || udp.DstPort == 67 || udp.SrcPort == 68 || udp.DstPort == 68 {
			if dhcpAlerts := nad.analyzeDHCP(packet); len(dhcpAlerts) > 0 {
				alerts = append(alerts, dhcpAlerts...)
			}
		}
	}
	
	// DNS analysis
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns := dnsLayer.(*layers.DNS)
		if dnsAlerts := nad.analyzeDNS(dns, packet); len(dnsAlerts) > 0 {
			alerts = append(alerts, dnsAlerts...)
		}
	}
	
	// WiFi analysis (802.11)
	if dot11Layer := packet.Layer(layers.LayerTypeDot11); dot11Layer != nil {
		if wifiAlerts := nad.analyzeWiFi(packet); len(wifiAlerts) > 0 {
			alerts = append(alerts, wifiAlerts...)
		}
	}
	
	// Add alerts to history
	nad.alerts = append(nad.alerts, alerts...)
	
	// Cleanup old data
	if len(nad.alerts) > 10000 {
		nad.alerts = nad.alerts[len(nad.alerts)-10000:]
	}
	
	return alerts
}

// MAC Spoofing Detection

func (nad *NetworkAttackDetector) trackIPMAC(ip, mac string) []AttackAlert {
	var alerts []AttackAlert
	
	if entry, exists := nad.ipMacMap[ip]; exists {
		if entry.MAC != mac {
			// MAC address changed for this IP
			event := MACChangeEvent{
				Timestamp:  time.Now(),
				IP:         ip,
				OldMAC:     entry.MAC,
				NewMAC:     mac,
				Suspicious: nad.isSuspiciousMACChange(entry.MAC, mac),
			}
			
			nad.macChangeLog = append(nad.macChangeLog, event)
			
			if event.Suspicious {
				alert := nad.createAlert("mac_spoofing", "high",
					fmt.Sprintf("MAC address spoofing detected for IP %s", ip),
					ip, mac, "", "",
					map[string]interface{}{
						"old_mac": entry.MAC,
						"new_mac": mac,
						"vendor_change": nad.getVendor(entry.MAC) != nad.getVendor(mac),
					})
				alerts = append(alerts, alert)
				nad.stats.MacSpoofing++
			}
			
			// Update entry
			entry.MAC = mac
			entry.LastSeen = time.Now()
		} else {
			entry.LastSeen = time.Now()
			entry.PacketCount++
		}
		nad.ipMacMap[ip] = entry
	} else {
		// New IP-MAC mapping
		nad.ipMacMap[ip] = MACEntry{
			IP:          ip,
			MAC:         mac,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			PacketCount: 1,
			Vendor:      nad.getVendor(mac),
		}
	}
	
	return alerts
}

func (nad *NetworkAttackDetector) isSuspiciousMACChange(oldMAC, newMAC string) bool {
	// Check if vendor changed (first 3 octets)
	if len(oldMAC) >= 8 && len(newMAC) >= 8 {
		return oldMAC[:8] != newMAC[:8]
	}
	return true
}

func (nad *NetworkAttackDetector) getVendor(mac string) string {
	// Simplified vendor lookup - in production would use OUI database
	if len(mac) < 8 {
		return "Unknown"
	}
	
	oui := mac[:8]
	vendorMap := map[string]string{
		"00:50:56": "VMware",
		"00:0C:29": "VMware",
		"00:1C:42": "Parallels",
		"08:00:27": "VirtualBox",
		"52:54:00": "QEMU/KVM",
		"00:15:5D": "Hyper-V",
	}
	
	if vendor, ok := vendorMap[oui]; ok {
		return vendor
	}
	
	return "Unknown"
}

// ARP Spoofing Detection

func (nad *NetworkAttackDetector) analyzeARP(arp *layers.ARP, packet gopacket.Packet) []AttackAlert {
	var alerts []AttackAlert
	
	srcIP := net.IP(arp.SourceProtAddress).String()
	srcMAC := net.HardwareAddr(arp.SourceHwAddress).String()
	dstIP := net.IP(arp.DstProtAddress).String()
	
	// Track ARP requests for flood detection
	nad.arpRequests[srcMAC] = append(nad.arpRequests[srcMAC], time.Now())
	
	// Check for ARP flooding
	if len(nad.arpRequests[srcMAC]) > 10 {
		// Clean old entries
		cutoff := time.Now().Add(-10 * time.Second)
		var recent []time.Time
		for _, t := range nad.arpRequests[srcMAC] {
			if t.After(cutoff) {
				recent = append(recent, t)
			}
		}
		nad.arpRequests[srcMAC] = recent
		
		if len(recent) > 10 {
			alert := nad.createAlert("arp_flood", "medium",
				"ARP request flood detected",
				srcIP, srcMAC, dstIP, "",
				map[string]interface{}{
					"request_count": len(recent),
					"time_window": "10s",
				})
			alerts = append(alerts, alert)
		}
	}
	
	// Check for gratuitous ARP (potential ARP poisoning)
	if arp.Operation == layers.ARPRequest && srcIP == dstIP {
		// Gratuitous ARP
		if entry, exists := nad.arpTable[srcIP]; exists {
			if entry.MAC != srcMAC {
				// MAC changed via gratuitous ARP - highly suspicious
				alert := nad.createAlert("arp_poisoning", "critical",
					fmt.Sprintf("ARP cache poisoning detected for IP %s", srcIP),
					srcIP, srcMAC, "", "",
					map[string]interface{}{
						"type": "gratuitous_arp",
						"old_mac": entry.MAC,
						"new_mac": srcMAC,
					})
				alerts = append(alerts, alert)
				nad.stats.ArpSpoofing++
			}
		}
		
		nad.arpTable[srcIP] = ARPEntry{
			IP:           srcIP,
			MAC:          srcMAC,
			LastUpdated:  time.Now(),
			IsGratuitous: true,
		}
	} else if arp.Operation == layers.ARPReply {
		// Check for unsolicited ARP replies
		if _, requested := nad.arpRequests[dstIP]; !requested {
			alert := nad.createAlert("arp_spoofing", "high",
				"Unsolicited ARP reply detected",
				srcIP, srcMAC, dstIP, "",
				map[string]interface{}{
					"type": "unsolicited_reply",
				})
			alerts = append(alerts, alert)
			nad.stats.ArpSpoofing++
		}
		
		// Update ARP table
		nad.arpTable[srcIP] = ARPEntry{
			IP:          srcIP,
			MAC:         srcMAC,
			LastUpdated: time.Now(),
		}
	}
	
	// Check for ARP spoofing patterns
	if arp.Operation == layers.ARPReply {
		// Multiple IPs claiming same MAC
		ipCount := 0
		for ip, entry := range nad.arpTable {
			if entry.MAC == srcMAC && ip != srcIP {
				ipCount++
			}
		}
		
		if ipCount > 0 {
			alert := nad.createAlert("arp_spoofing", "high",
				fmt.Sprintf("Multiple IPs (%d) using same MAC address", ipCount+1),
				srcIP, srcMAC, "", "",
				map[string]interface{}{
					"mac_address": srcMAC,
					"ip_count": ipCount + 1,
				})
			alerts = append(alerts, alert)
			nad.stats.ArpSpoofing++
		}
	}
	
	return alerts
}

// DHCP Attack Detection

func (nad *NetworkAttackDetector) analyzeDHCP(packet gopacket.Packet) []AttackAlert {
	var alerts []AttackAlert
	
	// Extract DHCP data from packet payload
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return alerts
	}
	
	payload := appLayer.Payload()
	if len(payload) < 240 { // Minimum DHCP packet size
		return alerts
	}
	
	// Simple DHCP message type detection
	msgType := nad.getDHCPMessageType(payload)
	
	netLayer := packet.NetworkLayer()
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	
	if netLayer == nil || ethLayer == nil {
		return alerts
	}
	
	eth := ethLayer.(*layers.Ethernet)
	srcIP := netLayer.NetworkFlow().Src().String()
	srcMAC := eth.SrcMAC.String()
	
	switch msgType {
	case 1: // DHCP Discover
		// Track DHCP requests for starvation attack
		nad.dhcpRequests[srcMAC] = append(nad.dhcpRequests[srcMAC], time.Now())
		
		// Check for DHCP starvation
		if len(nad.dhcpRequests[srcMAC]) > 5 {
			cutoff := time.Now().Add(-30 * time.Second)
			var recent []time.Time
			for _, t := range nad.dhcpRequests[srcMAC] {
				if t.After(cutoff) {
					recent = append(recent, t)
				}
			}
			nad.dhcpRequests[srcMAC] = recent
			
			if len(recent) > 5 {
				alert := nad.createAlert("dhcp_starvation", "high",
					"DHCP starvation attack detected",
					srcIP, srcMAC, "", "",
					map[string]interface{}{
						"request_count": len(recent),
						"time_window": "30s",
					})
				alerts = append(alerts, alert)
				nad.stats.DhcpAttacks++
			}
		}
		
	case 2: // DHCP Offer
		// Track DHCP servers
		if server, exists := nad.dhcpServers[srcIP]; exists {
			server.LastSeen = time.Now()
			server.OffersCount++
			nad.dhcpServers[srcIP] = server
		} else {
			nad.dhcpServers[srcIP] = DHCPServer{
				IP:          srcIP,
				MAC:         srcMAC,
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
				OffersCount: 1,
				Legitimate:  nad.isLegitDHCPServer(srcIP),
			}
		}
		
		// Check for rogue DHCP server
		if !nad.isLegitDHCPServer(srcIP) {
			alert := nad.createAlert("rogue_dhcp_server", "critical",
				"Rogue DHCP server detected",
				srcIP, srcMAC, "", "",
				map[string]interface{}{
					"server_ip": srcIP,
					"server_mac": srcMAC,
				})
			alerts = append(alerts, alert)
			nad.stats.DhcpAttacks++
		}
		
		// Check for multiple DHCP servers
		activeServers := 0
		for _, server := range nad.dhcpServers {
			if time.Since(server.LastSeen) < 5*time.Minute {
				activeServers++
			}
		}
		
		if activeServers > 1 {
			alert := nad.createAlert("multiple_dhcp_servers", "medium",
				fmt.Sprintf("Multiple DHCP servers detected (%d active)", activeServers),
				srcIP, srcMAC, "", "",
				map[string]interface{}{
					"server_count": activeServers,
				})
			alerts = append(alerts, alert)
		}
	}
	
	return alerts
}

func (nad *NetworkAttackDetector) getDHCPMessageType(payload []byte) byte {
	// Simple DHCP option parsing
	if len(payload) < 240 {
		return 0
	}
	
	// Skip to options (after 240 bytes of fixed fields)
	options := payload[240:]
	
	for i := 0; i < len(options)-2; i++ {
		if options[i] == 53 { // DHCP Message Type option
			return options[i+2]
		}
	}
	
	return 0
}

func (nad *NetworkAttackDetector) isLegitDHCPServer(ip string) bool {
	// In production, this would check against a whitelist
	// For now, assume router IPs are legitimate
	return ip == "192.168.1.1" || ip == "192.168.0.1" || ip == "10.0.0.1"
}

// DNS Hijacking Detection

func (nad *NetworkAttackDetector) analyzeDNS(dns *layers.DNS, packet gopacket.Packet) []AttackAlert {
	var alerts []AttackAlert
	
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return alerts
	}
	
	srcIP := netLayer.NetworkFlow().Src().String()
	dstIP := netLayer.NetworkFlow().Dst().String()
	
	if dns.QR { // DNS Response
		// Track DNS servers
		if server, exists := nad.dnsServers[srcIP]; exists {
			server.LastSeen = time.Now()
			server.ResponseCount++
			nad.dnsServers[srcIP] = server
		} else {
			nad.dnsServers[srcIP] = DNSServer{
				IP:            srcIP,
				FirstSeen:     time.Now(),
				LastSeen:      time.Now(),
				ResponseCount: 1,
				Legitimate:    nad.isLegitDNSServer(srcIP),
			}
		}
		
		// Check for DNS hijacking indicators
		if !nad.isLegitDNSServer(srcIP) {
			alert := nad.createAlert("dns_hijacking", "high",
				"DNS response from unauthorized server",
				srcIP, "", dstIP, "",
				map[string]interface{}{
					"dns_server": srcIP,
					"query_id": dns.ID,
				})
			alerts = append(alerts, alert)
			nad.stats.DnsHijacking++
		}
		
		// Check for cache poisoning attempts
		queryKey := fmt.Sprintf("%s:%d", dstIP, dns.ID)
		if queries, exists := nad.dnsQueries[queryKey]; exists && len(queries) > 0 {
			// Valid response to a query
			response := DNSResponse{
				Timestamp: time.Now(),
				QueryID:   dns.ID,
				ServerIP:  srcIP,
				ClientIP:  dstIP,
				Answers:   make([]string, 0),
			}
			
			// Extract answers
			for _, answer := range dns.Answers {
				if answer.Type == layers.DNSTypeA {
					response.Answers = append(response.Answers, answer.IP.String())
				}
			}
			
			// Check for suspicious responses
			if nad.isSuspiciousDNSResponse(response) {
				response.Suspicious = true
				alert := nad.createAlert("dns_hijacking", "high",
					"Suspicious DNS response detected",
					srcIP, "", dstIP, "",
					map[string]interface{}{
						"answers": response.Answers,
						"query_id": dns.ID,
					})
				alerts = append(alerts, alert)
				nad.stats.DnsHijacking++
			}
			
			nad.dnsResponses[queryKey] = append(nad.dnsResponses[queryKey], response)
		} else {
			// Unsolicited DNS response
			alert := nad.createAlert("dns_cache_poisoning", "critical",
				"Unsolicited DNS response - possible cache poisoning",
				srcIP, "", dstIP, "",
				map[string]interface{}{
					"query_id": dns.ID,
					"response_code": dns.ResponseCode.String(),
				})
			alerts = append(alerts, alert)
			nad.stats.DnsHijacking++
		}
	} else { // DNS Query
		for _, question := range dns.Questions {
			query := DNSQuery{
				Timestamp: time.Now(),
				QueryID:   dns.ID,
				ClientIP:  srcIP,
				ServerIP:  dstIP,
				QueryName: string(question.Name),
				QueryType: question.Type.String(),
			}
			
			queryKey := fmt.Sprintf("%s:%d", srcIP, dns.ID)
			nad.dnsQueries[queryKey] = append(nad.dnsQueries[queryKey], query)
			
			// Cleanup old queries
			if len(nad.dnsQueries[queryKey]) > 10 {
				nad.dnsQueries[queryKey] = nad.dnsQueries[queryKey][len(nad.dnsQueries[queryKey])-10:]
			}
		}
	}
	
	return alerts
}

func (nad *NetworkAttackDetector) isLegitDNSServer(ip string) bool {
	// Check against known DNS servers
	legitServers := []string{
		"8.8.8.8", "8.8.4.4", // Google
		"1.1.1.1", "1.0.0.1", // Cloudflare
		"9.9.9.9",            // Quad9
		"208.67.222.222",     // OpenDNS
		"192.168.1.1",        // Common router
		"192.168.0.1",
		"10.0.0.1",
	}
	
	for _, server := range legitServers {
		if ip == server {
			return true
		}
	}
	
	return false
}

func (nad *NetworkAttackDetector) isSuspiciousDNSResponse(response DNSResponse) bool {
	// Check for known malicious IPs in responses
	maliciousIPs := []string{
		"0.0.0.0",
		"127.0.0.1", // Localhost redirect
		"::1",       // IPv6 localhost
	}
	
	for _, answer := range response.Answers {
		for _, malIP := range maliciousIPs {
			if answer == malIP {
				return true
			}
		}
	}
	
	return false
}

// WiFi Attack Detection

func (nad *NetworkAttackDetector) analyzeWiFi(packet gopacket.Packet) []AttackAlert {
	var alerts []AttackAlert
	
	dot11 := packet.Layer(layers.LayerTypeDot11).(*layers.Dot11)
	
	// Deauthentication attack detection
	if dot11.Type == layers.Dot11TypeMgmtDeauthentication {
		deauth := DeauthEvent{
			Timestamp: time.Now(),
			SourceMAC: dot11.Address2.String(),
			DestMAC:   dot11.Address1.String(),
			BSSID:     dot11.Address3.String(),
		}
		
		nad.deauthPackets = append(nad.deauthPackets, deauth)
		
		// Check for deauth flood
		recentDeauths := 0
		cutoff := time.Now().Add(-10 * time.Second)
		for _, d := range nad.deauthPackets {
			if d.Timestamp.After(cutoff) && d.BSSID == deauth.BSSID {
				recentDeauths++
			}
		}
		
		if recentDeauths > 10 {
			alert := nad.createAlert("wifi_deauth_attack", "high",
				"WiFi deauthentication attack detected",
				"", deauth.SourceMAC, "", deauth.DestMAC,
				map[string]interface{}{
					"bssid": deauth.BSSID,
					"deauth_count": recentDeauths,
					"time_window": "10s",
				})
			alerts = append(alerts, alert)
			nad.stats.WiFiAttacks++
		}
	}
	
	// Beacon frame analysis for Evil Twin detection
	if dot11.Type == layers.Dot11TypeMgmtBeacon {
		if mgmtLayer := packet.Layer(layers.LayerTypeDot11MgmtBeacon); mgmtLayer != nil {
			beacon := BeaconFrame{
				Timestamp: time.Now(),
				BSSID:     dot11.Address3.String(),
			}
			
			// Extract SSID and other info
			// (Simplified - would need proper IE parsing)
			
			bssid := beacon.BSSID
			nad.beacons[bssid] = append(nad.beacons[bssid], beacon)
			
			// Check for Evil Twin (duplicate SSID with different BSSID)
			for otherBSSID, otherBeacons := range nad.beacons {
				if otherBSSID != bssid && len(otherBeacons) > 0 {
					if beacon.SSID == otherBeacons[0].SSID {
						alert := nad.createAlert("evil_twin_ap", "critical",
							fmt.Sprintf("Evil Twin AP detected - duplicate SSID: %s", beacon.SSID),
							"", beacon.BSSID, "", "",
							map[string]interface{}{
								"ssid": beacon.SSID,
								"legitimate_bssid": otherBSSID,
								"rogue_bssid": beacon.BSSID,
							})
						alerts = append(alerts, alert)
						nad.stats.WiFiAttacks++
					}
				}
			}
		}
	}
	
	// Probe request tracking
	if dot11.Type == layers.Dot11TypeMgmtProbeReq {
		client := nad.wifiClients[dot11.Address2.String()]
		client.MAC = dot11.Address2.String()
		client.LastSeen = time.Now()
		if client.FirstSeen.IsZero() {
			client.FirstSeen = time.Now()
		}
		
		// Track probe requests for client tracking
		nad.wifiClients[client.MAC] = client
	}
	
	return alerts
}

// VLAN Attack Detection

func (nad *NetworkAttackDetector) analyzeVLAN(vlan *layers.Dot1Q, packet gopacket.Packet) {
	vlanID := vlan.VLANIdentifier
	
	stats, exists := nad.vlanTraffic[vlanID]
	if !exists {
		stats = VLANStats{
			ID:        vlanID,
			FirstSeen: time.Now(),
		}
	}
	
	stats.PacketCount++
	stats.ByteCount += int64(len(packet.Data()))
	stats.LastSeen = time.Now()
	
	// Check for double tagging (VLAN hopping attack)
	if nextVLAN := packet.Layer(layers.LayerTypeDot1Q); nextVLAN != nil && nextVLAN != vlan {
		stats.DoubleTagged = true
		
		alert := nad.createAlert("vlan_hopping", "high",
			fmt.Sprintf("VLAN hopping attack detected - double tagged packet on VLAN %d", vlanID),
			"", "", "", "",
			map[string]interface{}{
				"outer_vlan": vlanID,
				"technique": "double_tagging",
			})
		nad.alerts = append(nad.alerts, alert)
		nad.stats.VlanAttacks++
	}
	
	nad.vlanTraffic[vlanID] = stats
}

// Monitor Mode Detection

func (nad *NetworkAttackDetector) detectMonitorMode(packet gopacket.Packet) bool {
	// Check for RadioTap header (indicates monitor mode capture)
	if packet.Layer(layers.LayerTypeRadioTap) != nil {
		return true
	}
	
	// Check for malformed packets that might indicate promiscuous mode
	if packet.ErrorLayer() != nil {
		// High number of malformed packets might indicate monitor mode
		return false // Need more sophisticated detection
	}
	
	return false
}

// Helper functions

func (nad *NetworkAttackDetector) createAlert(attackType, severity, description, srcIP, srcMAC, dstIP, dstMAC string, details map[string]interface{}) AttackAlert {
	return AttackAlert{
		Timestamp:   time.Now(),
		Type:        attackType,
		Severity:    severity,
		Description: description,
		SourceIP:    srcIP,
		SourceMAC:   srcMAC,
		DestIP:      dstIP,
		DestMAC:     dstMAC,
		Details:     details,
	}
}

// Getters

func (nad *NetworkAttackDetector) GetAlerts() []AttackAlert {
	nad.mu.RLock()
	defer nad.mu.RUnlock()
	
	return append([]AttackAlert{}, nad.alerts...)
}

func (nad *NetworkAttackDetector) GetStats() AttackStats {
	nad.mu.RLock()
	defer nad.mu.RUnlock()
	
	return nad.stats
}

func (nad *NetworkAttackDetector) GetMACChanges() []MACChangeEvent {
	nad.mu.RLock()
	defer nad.mu.RUnlock()
	
	return append([]MACChangeEvent{}, nad.macChangeLog...)
}

// Cleanup

func (nad *NetworkAttackDetector) Cleanup() {
	nad.mu.Lock()
	defer nad.mu.Unlock()
	
	// Clean old entries
	cutoff := time.Now().Add(-1 * time.Hour)
	
	// Clean MAC entries
	for ip, entry := range nad.ipMacMap {
		if entry.LastSeen.Before(cutoff) {
			delete(nad.ipMacMap, ip)
		}
	}
	
	// Clean ARP entries
	for ip, entry := range nad.arpTable {
		if entry.LastUpdated.Before(cutoff) {
			delete(nad.arpTable, ip)
		}
	}
	
	// Clean DNS queries
	for key, queries := range nad.dnsQueries {
		if len(queries) > 0 && queries[len(queries)-1].Timestamp.Before(cutoff) {
			delete(nad.dnsQueries, key)
		}
	}
	
	// Limit alert history
	if len(nad.alerts) > 10000 {
		nad.alerts = nad.alerts[len(nad.alerts)-10000:]
	}
}