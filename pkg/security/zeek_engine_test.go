package security

import (
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

func TestNewZeekEngine(t *testing.T) {
	engine := NewZeekEngine()
	assert.NotNil(t, engine)
	assert.NotNil(t, engine.events)
	assert.NotNil(t, engine.connections)
	assert.NotNil(t, engine.files)
	assert.NotNil(t, engine.notices)
	assert.NotNil(t, engine.scripts)
}

func TestZeekEngine_ProcessPacket(t *testing.T) {
	engine := NewZeekEngine()
	
	// Test with TCP packet
	packet := createTestPacket()
	events := engine.ProcessPacket(packet)
	assert.NotNil(t, events)
	
	// Should generate connection event
	if len(events) > 0 {
		assert.Contains(t, events[0].Type, "connection")
	}
	
	// Test with HTTP packet
	httpPayload := "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
	
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
		SrcPort: 54321,
		DstPort: 80,
		PSH:     true,
		ACK:     true,
		Seq:     1000,
		Ack:     2000,
	}
	
	tcp.SetNetworkLayerForChecksum(&ip)
	
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, gopacket.Payload(httpPayload))
	
	httpPacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	events = engine.ProcessPacket(httpPacket)
	assert.NotNil(t, events)
}

func TestZeekEngine_GetStats(t *testing.T) {
	engine := NewZeekEngine()
	
	// Process some packets
	packet := createTestPacket()
	engine.ProcessPacket(packet)
	engine.ProcessPacket(packet)
	
	stats := engine.GetStats()
	zeekStats, ok := stats.(ZeekStats)
	assert.True(t, ok)
	assert.Equal(t, uint64(2), zeekStats.TotalPackets)
	assert.NotNil(t, zeekStats.EventsByType)
	assert.NotNil(t, zeekStats.ProtocolStats)
}

func TestZeekEngine_GetEvents(t *testing.T) {
	engine := NewZeekEngine()
	
	// Initially no events
	events := engine.GetEvents()
	assert.Empty(t, events)
	
	// Process packet to generate events
	packet := createTestPacket()
	engine.ProcessPacket(packet)
	
	// Should have events now
	events = engine.GetEvents()
	assert.NotEmpty(t, events)
}

func TestZeekEngine_ClearEvents(t *testing.T) {
	engine := NewZeekEngine()
	
	// Process packet to generate events
	packet := createTestPacket()
	engine.ProcessPacket(packet)
	
	// Verify events exist
	events := engine.GetEvents()
	assert.NotEmpty(t, events)
	
	// Clear events
	engine.ClearEvents()
	
	// Verify events cleared
	events = engine.GetEvents()
	assert.Empty(t, events)
}

func TestZeekEngine_DNSProcessing(t *testing.T) {
	engine := NewZeekEngine()
	
	// Create DNS query
	dnsPacket := createDNSPacket("example.com", layers.DNSTypeA)
	events := engine.ProcessPacket(dnsPacket)
	
	assert.NotNil(t, events)
	// Should generate DNS event
	hasEvent := false
	for _, event := range events {
		if event.Type == "dns_query" {
			hasEvent = true
			assert.Contains(t, event.Details["query"], "example.com")
			break
		}
	}
	assert.True(t, hasEvent)
}

func TestZeekEngine_ConnectionTracking(t *testing.T) {
	engine := NewZeekEngine()
	
	// Create TCP SYN packet
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
		Seq:     1000,
	}
	
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	tcp.SetNetworkLayerForChecksum(&ip)
	gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp)
	
	synPacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	events := engine.ProcessPacket(synPacket)
	
	// Should generate connection event
	assert.NotEmpty(t, events)
	
	// Check connection tracking
	connID := "192.168.1.100:12345-192.168.1.200:80"
	conn, exists := engine.connections[connID]
	assert.True(t, exists)
	if exists {
		assert.Equal(t, "192.168.1.100", conn.OrigH)
		assert.Equal(t, 12345, conn.OrigP)
		assert.Equal(t, "192.168.1.200", conn.RespH)
		assert.Equal(t, 80, conn.RespP)
	}
}

func TestZeekEngine_HTTPSession(t *testing.T) {
	engine := NewZeekEngine()
	
	// Create HTTP request
	httpReq := "GET /test.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
	
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
		SrcPort: 54321,
		DstPort: 80,
		PSH:     true,
		ACK:     true,
	}
	
	tcp.SetNetworkLayerForChecksum(&ip)
	
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, gopacket.Payload(httpReq))
	
	httpPacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	events := engine.ProcessPacket(httpPacket)
	
	// Should generate HTTP request event
	hasHTTPEvent := false
	for _, event := range events {
		if event.Type == "http_request" {
			hasHTTPEvent = true
			assert.Equal(t, "GET", event.Details["method"])
			assert.Equal(t, "/test.html", event.Details["uri"])
			assert.Equal(t, "www.example.com", event.Details["host"])
			break
		}
	}
	assert.True(t, hasHTTPEvent)
}

func TestZeekEngine_SSLHandshake(t *testing.T) {
	engine := NewZeekEngine()
	
	// Simulate SSL/TLS Client Hello
	// This is a simplified version - real TLS is more complex
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
		SrcPort: 54321,
		DstPort: 443,
		PSH:     true,
		ACK:     true,
	}
	
	// TLS Client Hello (simplified)
	tlsPayload := []byte{
		0x16, 0x03, 0x01, // TLS record header
		0x00, 0x10,       // Length
		0x01,             // Handshake type: Client Hello
		// ... rest of handshake data
	}
	
	tcp.SetNetworkLayerForChecksum(&ip)
	
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, gopacket.Payload(tlsPayload))
	
	tlsPacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	events := engine.ProcessPacket(tlsPacket)
	
	// Should generate SSL event
	assert.NotNil(t, events)
}

func TestZeekEngine_FileTransfer(t *testing.T) {
	engine := NewZeekEngine()
	
	// Simulate file transfer event
	// Add a manual file for testing
	file := &ZeekFile{
		TS:           time.Now(),
		FUID:         "test-file-123",
		Source:       "HTTP",
		Depth:        0,
		SeenBytes:    1024000,
		TotalBytes:   1024000,
		MissingBytes: 0,
		MimeType:     "application/pdf",
		Filename:     "document.pdf",
		MD5:          "d41d8cd98f00b204e9800998ecf8427e",
		LocalOrig:    true,
		IsOrig:       true,
	}
	
	engine.files["test-file-123"] = file
	
	// Verify file tracking
	assert.Len(t, engine.files, 1)
	assert.Equal(t, "document.pdf", engine.files["test-file-123"].Filename)
}

func TestZeekStats_Fields(t *testing.T) {
	stats := ZeekStats{
		TotalPackets:     10000,
		TotalConnections: 250,
		TotalFiles:       25,
		TotalNotices:     10,
		TotalEvents:      500,
		EventsByType: map[string]uint64{
			"connection_established": 100,
			"dns_query":              200,
			"http_request":           150,
			"ssl_certificate":        50,
		},
		ServiceStats: map[string]uint64{
			"http": 300,
			"ssl":  150,
			"dns":  50,
		},
		ProtocolStats: map[string]uint64{
			"tcp":  7000,
			"udp":  2500,
			"icmp": 500,
		},
	}
	
	assert.Equal(t, uint64(10000), stats.TotalPackets)
	assert.Equal(t, uint64(500), stats.TotalEvents)
	assert.Equal(t, uint64(250), stats.TotalConnections)
	assert.Equal(t, uint64(25), stats.TotalFiles)
	assert.Equal(t, uint64(100), stats.EventsByType["connection_established"])
	assert.Equal(t, uint64(7000), stats.ProtocolStats["tcp"])
}

func TestZeekEvent_Fields(t *testing.T) {
	event := ZeekEvent{
		UID:       "CYqJ4z3J4vFjFhC5kb",
		Timestamp: time.Now(),
		Type:      "connection_established",
		Details: map[string]interface{}{
			"orig_h":     "192.168.1.100",
			"orig_p":     12345,
			"resp_h":     "192.168.1.200",
			"resp_p":     80,
			"proto":      "tcp",
			"service":    "http",
			"duration":   1.234,
			"orig_bytes": 1500,
			"resp_bytes": 5000,
		},
	}
	
	assert.Equal(t, "CYqJ4z3J4vFjFhC5kb", event.UID)
	assert.Equal(t, "connection_established", event.Type)
	assert.Equal(t, "192.168.1.100", event.Details["orig_h"])
	assert.Equal(t, 12345, event.Details["orig_p"])
	assert.Equal(t, 1.234, event.Details["duration"])
}

func TestZeekConnection_Fields(t *testing.T) {
	conn := ZeekConnection{
		TS:          time.Now(),
		UID:         "CYqJ4z3J4vFjFhC5kb",
		OrigH:       "192.168.1.100",
		OrigP:       54321,
		RespH:       "192.168.1.200",
		RespP:       443,
		Proto:       "tcp",
		Service:     "ssl",
		Duration:    5.678,
		OrigBytes:   2048,
		RespBytes:   8192,
		ConnState:   "SF",
		LocalOrig:   true,
		LocalResp:   false,
		MissedBytes: 0,
		History:     "ShADadFf",
		OrigPkts:    10,
		RespPkts:    15,
	}
	
	assert.Equal(t, "CYqJ4z3J4vFjFhC5kb", conn.UID)
	assert.Equal(t, "192.168.1.100", conn.OrigH)
	assert.Equal(t, 54321, conn.OrigP)
	assert.Equal(t, "ssl", conn.Service)
	assert.Equal(t, 5.678, conn.Duration)
	assert.Equal(t, int64(2048), conn.OrigBytes)
	assert.Equal(t, "SF", conn.ConnState)
}

func TestZeekFile_Fields(t *testing.T) {
	file := ZeekFile{
		TS:           time.Now(),
		FUID:         "FILE012",
		Source:       "HTTP",
		Depth:        0,
		SeenBytes:    2048576,
		TotalBytes:   2048576,
		MissingBytes: 0,
		MimeType:     "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		Filename:     "report.xlsx",
		MD5:          "098f6bcd4621d373cade4e832627b4f6",
		SHA1:         "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
		SHA256:       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Extracted:    "/tmp/zeek/extracted/FILE012.xlsx",
		LocalOrig:    false,
		IsOrig:       false,
	}
	
	assert.Equal(t, "FILE012", file.FUID)
	assert.Equal(t, "report.xlsx", file.Filename)
	assert.Equal(t, int64(2048576), file.SeenBytes)
	assert.Equal(t, "098f6bcd4621d373cade4e832627b4f6", file.MD5)
	assert.Equal(t, "/tmp/zeek/extracted/FILE012.xlsx", file.Extracted)
}

func TestZeekNotice_Fields(t *testing.T) {
	notice := ZeekNotice{
		TS:   time.Now(),
		UID:  "notice-001",
		Note: "Scan::Port_Scan",
		Msg:  "192.168.1.100 scanned at least 20 unique ports on host 192.168.1.200 in 0m0s",
		Sub:  "local",
		Src:  "192.168.1.100",
		Dst:  "192.168.1.200",
		P:    22,
		Actions: []string{
			"Notice::ACTION_LOG",
		},
		SuppressFor: 3600.0,
		Dropped:     false,
	}
	
	assert.Equal(t, "notice-001", notice.UID)
	assert.Equal(t, "Scan::Port_Scan", notice.Note)
	assert.Contains(t, notice.Msg, "scanned")
	assert.Equal(t, "192.168.1.100", notice.Src)
	assert.Equal(t, 22, notice.P)
	assert.False(t, notice.Dropped)
}