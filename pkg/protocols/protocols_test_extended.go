package protocols

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/stretchr/testify/assert"
)

// Test RegisterAnalyzer
func TestRegisterAnalyzer(t *testing.T) {
	pm := NewProtocolManager(100)
	
	// Create a mock analyzer
	mockAnalyzer := &mockAnalyzer{
		name: "MOCK",
		ports: []uint16{9999},
	}
	
	pm.RegisterAnalyzer(mockAnalyzer)
	
	analyzers := pm.GetAnalyzers()
	assert.Contains(t, analyzers, "MOCK")
}

// Test ProcessPacket
func TestProcessPacket(t *testing.T) {
	pm := NewProtocolManager(100)
	
	// Create a test TCP packet
	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP{192, 168, 1, 100},
		DstIP:    net.IP{192, 168, 1, 200},
	}
	
	tcp := layers.TCP{
		SrcPort: 50000,
		DstPort: 21, // FTP port
		SYN:     true,
		ACK:     false,
		Window:  1024,
	}
	
	tcp.SetNetworkLayerForChecksum(&ip)
	
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp)
	
	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	
	// Process packet - should not panic
	assert.NotPanics(t, func() {
		pm.ProcessPacket(packet)
	})
}

// Test ProcessPacket with nil
func TestProcessPacketNil(t *testing.T) {
	pm := NewProtocolManager(100)
	
	// Should handle nil gracefully
	assert.NotPanics(t, func() {
		pm.ProcessPacket(nil)
	})
}

// Test ProcessPacket with non-TCP packet
func TestProcessPacketNonTCP(t *testing.T) {
	pm := NewProtocolManager(100)
	
	// Create UDP packet
	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IP{192, 168, 1, 100},
		DstIP:    net.IP{192, 168, 1, 200},
	}
	
	udp := layers.UDP{
		SrcPort: 12345,
		DstPort: 53,
	}
	
	udp.SetNetworkLayerForChecksum(&ip)
	
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp)
	
	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	
	// Should handle non-TCP packets gracefully
	assert.NotPanics(t, func() {
		pm.ProcessPacket(packet)
	})
}

// Test GetEvents
func TestGetEvents(t *testing.T) {
	pm := NewProtocolManager(100)
	
	// Initially should have empty events
	events := pm.GetEvents()
	assert.NotNil(t, events)
	
	// Add an event through the channel
	testEvent := ProtocolEvent{
		ID:        "TEST_001",
		Protocol:  "TEST",
		EventType: EventTypeCommand,
		Timestamp: time.Now(),
	}
	
	// Send event to channel
	select {
	case pm.events <- testEvent:
		// Event sent successfully
	default:
		// Channel might be full
	}
	
	// Get events again
	events = pm.GetEvents()
	assert.NotNil(t, events)
}

// Test FlushConnections
func TestFlushConnections(t *testing.T) {
	pm := NewProtocolManager(100)
	
	// Should not panic
	assert.NotPanics(t, func() {
		pm.FlushConnections()
	})
}

// Test concurrent access
func TestProtocolManagerConcurrency(t *testing.T) {
	pm := NewProtocolManager(100)
	
	done := make(chan bool, 10)
	
	// Multiple goroutines processing packets
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- true }()
			
			// Create different packets
			eth := layers.Ethernet{
				SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, byte(id)},
				DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
				EthernetType: layers.EthernetTypeIPv4,
			}
			
			ip := layers.IPv4{
				Version:  4,
				TTL:      64,
				Protocol: layers.IPProtocolTCP,
				SrcIP:    net.IP{192, 168, 1, byte(100 + id)},
				DstIP:    net.IP{192, 168, 1, 200},
			}
			
			tcp := layers.TCP{
				SrcPort: layers.TCPPort(50000 + id),
				DstPort: 21,
				SYN:     true,
				Window:  1024,
			}
			
			tcp.SetNetworkLayerForChecksum(&ip)
			
			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
			gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp)
			
			packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
			pm.ProcessPacket(packet)
		}(i)
	}
	
	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// Mock analyzer for testing
type mockAnalyzer struct {
	name  string
	ports []uint16
}

func (m *mockAnalyzer) GetProtocolName() string {
	return m.name
}

func (m *mockAnalyzer) GetPorts() []uint16 {
	return m.ports
}

func (m *mockAnalyzer) AnalyzeStream(flow gopacket.Flow, reader *tcpreader.ReaderStream) []ProtocolEvent {
	return []ProtocolEvent{}
}

func (m *mockAnalyzer) IsProtocolTraffic(data []byte) bool {
	return false
}

// Test specific protocol analyzers in more detail
func TestFTPAnalyzerDetails(t *testing.T) {
	analyzer := NewFTPAnalyzer()
	
	// Test various FTP commands
	ftpCommands := []string{
		"220 FTP Server Ready\r\n",
		"USER anonymous\r\n",
		"PASS guest@example.com\r\n",
		"LIST\r\n",
		"RETR file.txt\r\n",
		"STOR upload.txt\r\n",
		"QUIT\r\n",
		"230 User logged in\r\n",
		"550 File not found\r\n",
	}
	
	for _, cmd := range ftpCommands {
		result := analyzer.IsProtocolTraffic([]byte(cmd))
		assert.True(t, result, "Expected FTP traffic for: %s", cmd)
	}
	
	// Test non-FTP traffic
	nonFTPData := []string{
		"GET / HTTP/1.1\r\n",
		"EHLO mail.example.com\r\n",
		"SSH-2.0-OpenSSH\r\n",
	}
	
	for _, data := range nonFTPData {
		result := analyzer.IsProtocolTraffic([]byte(data))
		assert.False(t, result, "Expected non-FTP traffic for: %s", data)
	}
}

func TestSMTPAnalyzerDetails(t *testing.T) {
	analyzer := NewSMTPAnalyzer()
	
	// Test SMTP commands and responses
	smtpData := []string{
		"220 mail.example.com ESMTP\r\n",
		"EHLO client.example.com\r\n",
		"HELO client.example.com\r\n",
		"MAIL FROM:<sender@example.com>\r\n",
		"RCPT TO:<recipient@example.com>\r\n",
		"DATA\r\n",
		"QUIT\r\n",
		"250 OK\r\n",
		"354 Start mail input\r\n",
		"550 User unknown\r\n",
	}
	
	for _, data := range smtpData {
		result := analyzer.IsProtocolTraffic([]byte(data))
		assert.True(t, result, "Expected SMTP traffic for: %s", data)
	}
}

func TestIMAPAnalyzerDetails(t *testing.T) {
	analyzer := NewIMAPAnalyzer()
	
	// Test IMAP commands and responses
	imapData := []string{
		"* OK IMAP4rev1 Service Ready\r\n",
		"A001 LOGIN user pass\r\n",
		"A002 SELECT INBOX\r\n",
		"A003 FETCH 1 BODY[]\r\n",
		"A004 LOGOUT\r\n",
		"* 10 EXISTS\r\n",
		"A001 OK LOGIN completed\r\n",
	}
	
	for _, data := range imapData {
		result := analyzer.IsProtocolTraffic([]byte(data))
		assert.True(t, result, "Expected IMAP traffic for: %s", data)
	}
}

func TestPOP3AnalyzerDetails(t *testing.T) {
	analyzer := NewPOP3Analyzer()
	
	// Test POP3 commands and responses
	pop3Data := []string{
		"+OK POP3 server ready\r\n",
		"USER john\r\n",
		"PASS secret\r\n",
		"STAT\r\n",
		"LIST\r\n",
		"RETR 1\r\n",
		"DELE 1\r\n",
		"QUIT\r\n",
		"-ERR Invalid command\r\n",
	}
	
	for _, data := range pop3Data {
		result := analyzer.IsProtocolTraffic([]byte(data))
		assert.True(t, result, "Expected POP3 traffic for: %s", data)
	}
}

func TestSSHAnalyzerDetails(t *testing.T) {
	analyzer := NewSSHAnalyzer()
	
	// Test SSH version strings
	sshData := []string{
		"SSH-2.0-OpenSSH_8.2\r\n",
		"SSH-1.99-OpenSSH_7.4\r\n",
		"SSH-2.0-libssh2_1.8.0\r\n",
	}
	
	for _, data := range sshData {
		result := analyzer.IsProtocolTraffic([]byte(data))
		assert.True(t, result, "Expected SSH traffic for: %s", data)
	}
	
	// Test non-SSH traffic
	result := analyzer.IsProtocolTraffic([]byte("GET / HTTP/1.1\r\n"))
	assert.False(t, result)
}

func TestIRCAnalyzerDetails(t *testing.T) {
	analyzer := NewIRCAnalyzer()
	
	// Test IRC commands
	ircData := []string{
		"NICK johndoe\r\n",
		"USER john 0 * :John Doe\r\n",
		"JOIN #channel\r\n",
		"PRIVMSG #channel :Hello world\r\n",
		"QUIT :Goodbye\r\n",
		":server 001 user :Welcome\r\n",
		":user!user@host PRIVMSG #channel :Hi\r\n",
	}
	
	for _, data := range ircData {
		result := analyzer.IsProtocolTraffic([]byte(data))
		assert.True(t, result, "Expected IRC traffic for: %s", data)
	}
}

// Benchmark tests
func BenchmarkProcessPacket(b *testing.B) {
	pm := NewProtocolManager(1000)
	
	// Create test packet
	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP{192, 168, 1, 100},
		DstIP:    net.IP{192, 168, 1, 200},
	}
	
	tcp := layers.TCP{
		SrcPort: 50000,
		DstPort: 21,
		PSH:     true,
		ACK:     true,
		Window:  1024,
	}
	
	tcp.SetNetworkLayerForChecksum(&ip)
	
	payload := []byte("USER anonymous\r\n")
	
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, gopacket.Payload(payload))
	
	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pm.ProcessPacket(packet)
	}
}

func BenchmarkIsProtocolTraffic(b *testing.B) {
	analyzer := NewFTPAnalyzer()
	data := []byte("220 FTP Server Ready\r\n")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.IsProtocolTraffic(data)
	}
}