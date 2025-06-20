package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to create test certificate and key
func createTestCertAndKey(t *testing.T) (certFile, keyFile string) {
	// Generate RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost", "test.example.com"},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)

	// Create temp directory
	tmpDir := t.TempDir()

	// Write certificate
	certFile = filepath.Join(tmpDir, "test.crt")
	certOut, err := os.Create(certFile)
	require.NoError(t, err)
	defer func() {
		if err := certOut.Close(); err != nil {
			t.Logf("Failed to close cert file: %v", err)
		}
	}()

	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	require.NoError(t, err)

	// Write key
	keyFile = filepath.Join(tmpDir, "test.key")
	keyOut, err := os.Create(keyFile)
	require.NoError(t, err)
	defer func() {
		if err := keyOut.Close(); err != nil {
			t.Logf("Failed to close key file: %v", err)
		}
	}()

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	err = pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	require.NoError(t, err)

	return certFile, keyFile
}

// Helper to create test key log file
func createTestKeyLogFile(t *testing.T) string {
	content := `# SSL/TLS secrets log file
CLIENT_RANDOM 52cb20b96d31e6c6bfde70317fb569a4d476e5b6b6905c0b5c73c79a4b055c73 7a8865f63b41e6b3a8f5fca31275b7ab06f96c8e90177de3e693e96fcc3e95ab7abe2b5ba91f10bb8e58dd8f322c2e9f
CLIENT_RANDOM 52cb20ba4a96de7a3858c4c5f87e4a62b193bbbcc64c7dd08f8b1d209c8c6e96 85e3f5e39b71f9a3f8a0b1b8e7e0e5a1e3f3b8e17e8e3a1f8e1b3e8a7e0b5a1e3f
`
	tmpFile := filepath.Join(t.TempDir(), "keylog.txt")
	// Use secure permissions for test files
	err := os.WriteFile(tmpFile, []byte(content), 0600)
	require.NoError(t, err)
	return tmpFile
}

// Helper to create test TLS packet
func createTestTLSPacket(srcIP, dstIP string, srcPort, dstPort uint16, tlsData []byte) gopacket.Packet {
	// Create layers
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     12345,
		Window:  14600,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		// Log error but continue as this is test data
		fmt.Printf("Warning: failed to set network layer for checksum: %v\n", err)
	}

	// Create packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(tlsData)); err != nil {
		// Return a basic packet on error
		return gopacket.NewPacket([]byte{}, layers.LayerTypeEthernet, gopacket.Default)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// Test TLSDecryptor creation
func TestNewTLSDecryptor(t *testing.T) {
	td := NewTLSDecryptor()
	assert.NotNil(t, td)
	assert.NotNil(t, td.sessions)
	assert.NotNil(t, td.privateKeys)
	assert.NotNil(t, td.keyLogEntries)
}

// Test loading private key
func TestLoadPrivateKey(t *testing.T) {
	td := NewTLSDecryptor()
	certFile, keyFile := createTestCertAndKey(t)

	// Test loading valid key
	err := td.LoadPrivateKey("test.example.com", certFile, keyFile)
	assert.NoError(t, err)
	assert.Len(t, td.privateKeys, 1)

	// Test loading non-existent file
	err = td.LoadPrivateKey("test.example.com", "/non/existent/file.crt", "/non/existent/file.key")
	assert.Error(t, err)

	// Test loading invalid PEM
	invalidFile := filepath.Join(t.TempDir(), "invalid.key")
	// Use secure permissions for test files
	err = os.WriteFile(invalidFile, []byte("not a valid pem"), 0600)
	require.NoError(t, err)
	err = td.LoadPrivateKey("test.example.com", certFile, invalidFile)
	assert.Error(t, err)
}

// Test loading key log file
func TestLoadKeyLogFile(t *testing.T) {
	td := NewTLSDecryptor()
	keyLogFile := createTestKeyLogFile(t)

	// Test loading valid file
	err := td.LoadKeyLogFile(keyLogFile)
	assert.NoError(t, err)
	assert.Len(t, td.keyLogEntries, 2)

	// Test loading non-existent file
	err = td.LoadKeyLogFile("/non/existent/file.txt")
	assert.Error(t, err)

	// Test loading file with invalid format
	invalidFile := filepath.Join(t.TempDir(), "invalid.txt")
	// Use secure permissions for test files
	err = os.WriteFile(invalidFile, []byte("invalid format\nno valid entries"), 0600)
	require.NoError(t, err)
	err = td.LoadKeyLogFile(invalidFile)
	assert.NoError(t, err) // Should not error, just skip invalid lines
}

// Test processing TLS packets
func TestProcessTLSPacket(t *testing.T) {
	td := NewTLSDecryptor()

	// Test with non-TLS packet (HTTP)
	httpPacket := createTestTLSPacket("192.168.1.100", "192.168.1.200", 50000, 80, []byte("GET / HTTP/1.1\r\n"))
	data, err := td.ProcessTLSPacket(httpPacket)
	assert.Nil(t, data)
	assert.Error(t, err)

	// Test with TLS client hello
	clientHello := []byte{
		0x16,       // Content Type: Handshake
		0x03, 0x01, // Version: TLS 1.0
		0x00, 0x05, // Length: 5 bytes
		0x01,             // Handshake Type: Client Hello
		0x00, 0x00, 0x01, // Handshake Length: 1
		0x00, // Minimal client hello data
	}
	tlsPacket := createTestTLSPacket("192.168.1.100", "192.168.1.200", 50000, 443, clientHello)
	data, err = td.ProcessTLSPacket(tlsPacket)
	assert.NotNil(t, data)
	assert.NoError(t, err)
	assert.Equal(t, "TLS-ClientHello", data.Protocol)

	// Test with malformed TLS data
	malformedTLS := []byte{0x16, 0x03} // Too short
	malformedPacket := createTestTLSPacket("192.168.1.100", "192.168.1.200", 50000, 443, malformedTLS)
	data, err = td.ProcessTLSPacket(malformedPacket)
	assert.Nil(t, data)
	assert.Error(t, err)
}

// Test TLS record processing
func TestProcessTLSRecord(t *testing.T) {
	td := NewTLSDecryptor()

	// Create a session
	sessionID := "192.168.1.100:50000->192.168.1.200:443"
	session := &TLSSession{
		ClientIP:   net.ParseIP("192.168.1.100"),
		ServerIP:   net.ParseIP("192.168.1.200"),
		ClientPort: 50000,
		ServerPort: 443,
		State:      TLSStateHandshake,
	}
	td.sessions[sessionID] = session

	// Test processing alert
	alertRecord := []byte{
		0x15,       // Content Type: Alert
		0x03, 0x03, // Version: TLS 1.2
		0x00, 0x02, // Length: 2 bytes
		0x01, 0x00, // Alert: Warning, Close Notify
	}
	data, err := td.processTLSRecord(session, alertRecord, time.Now().Unix())
	assert.NotNil(t, data)
	assert.NoError(t, err)
	assert.Equal(t, "TLS-Alert", data.Protocol)

	// Test processing change cipher spec
	ccsRecord := []byte{
		0x14,       // Content Type: ChangeCipherSpec
		0x03, 0x03, // Version: TLS 1.2
		0x00, 0x01, // Length: 1 byte
		0x01, // Change Cipher Spec
	}
	data, err = td.processTLSRecord(session, ccsRecord, time.Now().Unix())
	assert.NotNil(t, data)
	assert.NoError(t, err)
	assert.Equal(t, "TLS-ChangeCipherSpec", data.Protocol)

	// Test processing application data
	appDataRecord := []byte{
		0x17,       // Content Type: Application Data
		0x03, 0x03, // Version: TLS 1.2
		0x00, 0x05, // Length: 5 bytes
		0x01, 0x02, 0x03, 0x04, 0x05, // Encrypted data
	}
	data, err = td.processTLSRecord(session, appDataRecord, time.Now().Unix())
	assert.NotNil(t, data)
	assert.NoError(t, err)
	assert.Equal(t, "TLS-Encrypted", data.Protocol)
}

// Test handshake processing
func TestProcessHandshake(t *testing.T) {
	td := NewTLSDecryptor()

	session := &TLSSession{
		State: TLSStateHandshake,
	}

	// Test server hello
	serverHello := []byte{
		0x02,             // Handshake Type: Server Hello
		0x00, 0x00, 0x26, // Length: 38 bytes
		0x03, 0x03, // Version: TLS 1.2
		// 32 bytes random
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x00,       // Session ID length
		0x00, 0x2f, // Cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA
		0x00, // Compression method: none
	}
	if _, err := td.processHandshake(session, serverHello, time.Now().Unix()); err != nil {
		t.Errorf("Failed to process server hello: %v", err)
	}
	assert.Equal(t, uint16(0x002f), session.CipherSuite)

	// Test certificate
	certificate := []byte{
		0x0b,             // Handshake Type: Certificate
		0x00, 0x00, 0x03, // Length: 3 bytes
		0x00, 0x00, 0x00, // Certificate list length: 0 (simplified)
	}
	if _, err := td.processHandshake(session, certificate, time.Now().Unix()); err != nil {
		t.Errorf("Failed to process certificate: %v", err)
	}
	// No assertions as it's a simplified test

	// Test client key exchange
	clientKeyExchange := []byte{
		0x10,             // Handshake Type: Client Key Exchange
		0x00, 0x00, 0x02, // Length: 2 bytes
		0x00, 0x00, // Encrypted pre-master secret (simplified)
	}
	if _, err := td.processHandshake(session, clientKeyExchange, time.Now().Unix()); err != nil {
		t.Errorf("Failed to process client key exchange: %v", err)
	}
	// Check state after key exchange
	assert.Equal(t, TLSStateEstablished, session.State)
}

// Test client hello processing
func TestProcessClientHello(t *testing.T) {
	td := NewTLSDecryptor()
	session := &TLSSession{}

	// Client hello with SNI
	clientHello := []byte{
		0x03, 0x03, // Version: TLS 1.2
		// 32 bytes random
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x00,       // Session ID length
		0x00, 0x02, // Cipher suites length
		0x00, 0x2f, // Cipher suite
		0x01, // Compression methods length
		0x00, // Compression method
		// Extensions would go here for SNI
	}

	if _, err := td.processClientHello(session, clientHello, time.Now().Unix()); err != nil {
		t.Errorf("Failed to process client hello: %v", err)
	}
	// Basic test without SNI extension
}

// Test alert processing
func TestProcessAlert(t *testing.T) {
	td := NewTLSDecryptor()
	session := &TLSSession{}

	// Test various alert types
	alerts := []struct {
		level       byte
		description byte
		expectError bool
	}{
		{0x01, 0x00, false}, // Warning, Close Notify
		{0x02, 0x0A, true},  // Fatal, Unexpected Message
		{0x02, 0x14, true},  // Fatal, Bad Record MAC
		{0x02, 0x28, true},  // Fatal, Handshake Failure
	}

	for _, alert := range alerts {
		alertData := []byte{alert.level, alert.description}
		if _, err := td.processAlert(session, alertData, time.Now().Unix()); err != nil {
			t.Errorf("Failed to process alert: %v", err)
		}
		if alert.expectError {
			assert.Equal(t, TLSStateClosed, session.State)
		}
	}
}

// Test SNI extraction
func TestExtractSNI(t *testing.T) {
	td := &TLSDecryptor{}

	// Extensions with SNI
	extensions := []byte{
		0x00, 0x00, // Extension Type: Server Name
		0x00, 0x10, // Extension Length: 16
		0x00, 0x0e, // Server Name List Length: 14
		0x00,       // Server Name Type: host_name
		0x00, 0x0b, // Server Name Length: 11
		// "example.com" (without null terminator)
		0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
	}

	sni := td.extractSNI(extensions)
	assert.Equal(t, "example.com", sni)

	// Extensions without SNI
	noSNI := []byte{
		0x00, 0x0b, // Extension Type: EC Point Formats
		0x00, 0x02, // Extension Length
		0x01, 0x00, // Data
	}
	sni = td.extractSNI(noSNI)
	assert.Equal(t, "", sni)

	// Empty extensions
	sni = td.extractSNI([]byte{})
	assert.Equal(t, "", sni)
}

// Test content type detection
func TestDetectContentType(t *testing.T) {
	td := &TLSDecryptor{}

	tests := []struct {
		data        []byte
		expected    ContentType
		description string
	}{
		{[]byte("GET / HTTP/1.1\r\n"), ContentTypeHTTP, "HTTP GET request"},
		{[]byte("HTTP/1.1 200 OK\r\n"), ContentTypeHTTP, "HTTP response"},
		{[]byte("POST /api HTTP/1.1\r\n"), ContentTypeHTTP, "HTTP POST request"},
		{[]byte("{\"key\": \"value\"}"), ContentTypeJSON, "JSON object"},
		{[]byte("[1, 2, 3]"), ContentTypeJSON, "JSON array"},
		{[]byte("<?xml version=\"1.0\"?>"), ContentTypeXML, "XML declaration"},
		{[]byte("<root>data</root>"), ContentTypeXML, "XML element"},
		{[]byte("\x00\x01\x02\x03"), ContentTypeBinary, "Binary data"},
		{[]byte("plain text"), ContentTypeBinary, "Plain text (default to binary)"},
	}

	for _, tt := range tests {
		contentType := td.detectContentType(tt.data)
		assert.Equal(t, tt.expected, contentType, tt.description)
	}
}

// Test hex to bytes conversion
func TestHexToBytes(t *testing.T) {
	tests := []struct {
		hex      string
		expected []byte
		hasError bool
	}{
		{"48656c6c6f", []byte("Hello"), false},
		{"00010203", []byte{0, 1, 2, 3}, false},
		{"", []byte{}, false},
		{"invalid", nil, true},
		{"12g4", nil, true},
	}

	for _, tt := range tests {
		result, err := hexToBytes(tt.hex)
		if tt.hasError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		}
	}
}

// Test session management
func TestSessionManagement(t *testing.T) {
	td := NewTLSDecryptor()

	// Create some sessions
	for i := 0; i < 3; i++ {
		sessionID := fmt.Sprintf("session-%d", i)
		td.sessions[sessionID] = &TLSSession{
			ClientIP:   net.ParseIP(fmt.Sprintf("192.168.1.%d", i+1)),
			ServerIP:   net.ParseIP("192.168.1.200"),
			ClientPort: uint16(50000 + (i % 15535)), // Prevent overflow
			ServerPort: 443,
			State:      TLSStateEstablished,
			ServerName: fmt.Sprintf("server%d.example.com", i),
		}
		if i == 0 {
			td.sessions[sessionID].State = TLSStateClosed
		}
	}

	// Test GetActiveSessions
	activeSessions := td.GetActiveSessions()
	assert.Len(t, activeSessions, 2) // Only established sessions

	// Test GetSessionStats
	stats := td.GetSessionStats()
	assert.Equal(t, 3, stats["total_sessions"])
	assert.Equal(t, 2, stats["active_sessions"])
	assert.Equal(t, 0, stats["decrypted_count"])
}

// Test concurrent access
func TestConcurrentAccess(t *testing.T) {
	td := NewTLSDecryptor()

	// Load some initial data
	certFile, keyFile := createTestCertAndKey(t)
	err := td.LoadPrivateKey("test.example.com", certFile, keyFile)
	require.NoError(t, err)

	done := make(chan bool)

	// Concurrent packet processing
	for i := 0; i < 10; i++ {
		go func(id int) {
			clientHello := []byte{
				0x16, 0x03, 0x01, 0x00, 0x05,
				0x01, 0x00, 0x00, 0x01, 0x00,
			}
			packet := createTestTLSPacket(
				fmt.Sprintf("192.168.1.%d", id),
				"192.168.1.200",
				uint16(50000+(id%15535)), // Prevent overflow
				443,
				clientHello,
			)
			if _, err := td.ProcessTLSPacket(packet); err != nil {
				t.Errorf("Failed to process TLS packet: %v", err)
			}
			done <- true
		}(i)
	}

	// Concurrent stats reading
	for i := 0; i < 5; i++ {
		go func() {
			td.GetActiveSessions()
			td.GetSessionStats()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 15; i++ {
		<-done
	}

	// Verify no panic occurred
	assert.True(t, true)
}

// Benchmark tests
func BenchmarkProcessTLSPacket(b *testing.B) {
	td := NewTLSDecryptor()
	clientHello := []byte{
		0x16, 0x03, 0x01, 0x00, 0x05,
		0x01, 0x00, 0x00, 0x01, 0x00,
	}
	packet := createTestTLSPacket("192.168.1.100", "192.168.1.200", 50000, 443, clientHello)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		td.ProcessTLSPacket(packet)
	}
}

func BenchmarkHexToBytes(b *testing.B) {
	hex := "48656c6c6f20576f726c642048656c6c6f20576f726c64"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = hexToBytes(hex)
	}
}

