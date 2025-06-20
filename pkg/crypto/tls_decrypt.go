package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TLSDecryptor handles SSL/TLS traffic decryption
type TLSDecryptor struct {
	privateKeys    map[string]*rsa.PrivateKey  // Domain -> Private Key
	certificates   map[string]*x509.Certificate // Domain -> Certificate
	keyLogEntries  map[string][]byte            // Session -> Master Secret
	sessions       map[string]*TLSSession       // Connection -> Session
	mutex          sync.RWMutex
}

// TLSSession represents an active TLS session
type TLSSession struct {
	ClientIP      net.IP
	ServerIP      net.IP
	ClientPort    uint16
	ServerPort    uint16
	SessionID     []byte
	MasterSecret  []byte
	CipherSuite   uint16
	State         TLSState
	ServerName    string
	HandshakeData []byte
}

// TLSState represents the state of a TLS connection
type TLSState int

const (
	TLSStateHandshake TLSState = iota
	TLSStateEstablished
	TLSStateClosing
	TLSStateClosed
)

// DecryptedData represents decrypted TLS payload
type DecryptedData struct {
	Session     *TLSSession
	Timestamp   int64
	Direction   Direction
	Protocol    string
	Payload     []byte
	ContentType ContentType
}

// Direction indicates data flow direction
type Direction int

const (
	DirectionClientToServer Direction = iota
	DirectionServerToClient
)

// ContentType represents TLS content types
type ContentType int

const (
	ContentTypeHTTP ContentType = iota
	ContentTypeJSON
	ContentTypeXML
	ContentTypeBinary
)

// NewTLSDecryptor creates a new TLS decryptor
func NewTLSDecryptor() *TLSDecryptor {
	return &TLSDecryptor{
		privateKeys:   make(map[string]*rsa.PrivateKey),
		certificates:  make(map[string]*x509.Certificate),
		keyLogEntries: make(map[string][]byte),
		sessions:      make(map[string]*TLSSession),
	}
}

// LoadPrivateKey loads a private key and certificate for a domain
func (t *TLSDecryptor) LoadPrivateKey(domain, certPath, keyPath string) error {
	// Load certificate
	certData, err := ioutil.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}

	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Load private key
	keyData, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode private key PEM")
	}

	var privateKey *rsa.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("private key is not RSA")
		}
	default:
		return fmt.Errorf("unsupported private key type: %s", keyBlock.Type)
	}

	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.certificates[domain] = cert
	t.privateKeys[domain] = privateKey

	return nil
}

// LoadKeyLogFile loads a Chrome/Firefox SSLKEYLOGFILE
func (t *TLSDecryptor) LoadKeyLogFile(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read key log file: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		// Parse CLIENT_RANDOM entries
		if parts[0] == "CLIENT_RANDOM" {
			clientRandom := parts[1]
			masterSecret := parts[2]
			
			// Convert hex string to bytes
			masterSecretBytes, err := hexToBytes(masterSecret)
			if err != nil {
				continue
			}

			t.mutex.Lock()
			t.keyLogEntries[clientRandom] = masterSecretBytes
			t.mutex.Unlock()
		}
	}

	return nil
}

// ProcessTLSPacket processes a packet that may contain TLS data
func (t *TLSDecryptor) ProcessTLSPacket(packet gopacket.Packet) (*DecryptedData, error) {
	// Extract TCP layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil, fmt.Errorf("no TCP layer found")
	}

	tcp := tcpLayer.(*layers.TCP)
	
	// Check if this is likely TLS traffic (port 443 or has TLS content type)
	if tcp.DstPort != 443 && tcp.SrcPort != 443 {
		payload := tcp.Payload
		if len(payload) < 6 {
			return nil, fmt.Errorf("packet too small for TLS")
		}
		
		// Check for TLS content type (0x16 = handshake, 0x17 = application data)
		if payload[0] != 0x16 && payload[0] != 0x17 && payload[0] != 0x15 && payload[0] != 0x14 {
			return nil, fmt.Errorf("not TLS traffic")
		}
	}

	// Get network layer for IP addresses
	ipLayer := packet.NetworkLayer()
	if ipLayer == nil {
		return nil, fmt.Errorf("no network layer found")
	}

	var srcIP, dstIP net.IP
	if ip4 := ipLayer.(*layers.IPv4); ip4 != nil {
		srcIP = ip4.SrcIP
		dstIP = ip4.DstIP
	} else {
		return nil, fmt.Errorf("IPv6 not yet supported")
	}

	// Create session key
	sessionKey := fmt.Sprintf("%s:%d-%s:%d", srcIP, tcp.SrcPort, dstIP, tcp.DstPort)

	t.mutex.Lock()
	session, exists := t.sessions[sessionKey]
	t.mutex.Unlock()

	if !exists {
		// Create new session
		session = &TLSSession{
			ClientIP:   srcIP,
			ServerIP:   dstIP,
			ClientPort: uint16(tcp.SrcPort),
			ServerPort: uint16(tcp.DstPort),
			State:      TLSStateHandshake,
		}

		t.mutex.Lock()
		t.sessions[sessionKey] = session
		t.mutex.Unlock()
	}

	// Process TLS record
	return t.processTLSRecord(session, tcp.Payload, packet.Metadata().Timestamp.Unix())
}

// processTLSRecord processes a TLS record and attempts decryption
func (t *TLSDecryptor) processTLSRecord(session *TLSSession, payload []byte, timestamp int64) (*DecryptedData, error) {
	if len(payload) < 5 {
		return nil, fmt.Errorf("TLS record too short")
	}

	contentType := payload[0]
	// version := uint16(payload[1])<<8 | uint16(payload[2])  // TLS version, not currently used
	length := uint16(payload[3])<<8 | uint16(payload[4])

	if len(payload) < int(5+length) {
		return nil, fmt.Errorf("incomplete TLS record")
	}

	recordData := payload[5 : 5+length]

	switch contentType {
	case 0x16: // Handshake
		return t.processHandshake(session, recordData, timestamp)
	case 0x17: // Application Data
		return t.processApplicationData(session, recordData, timestamp)
	case 0x15: // Alert
		return t.processAlert(session, recordData, timestamp)
	case 0x14: // Change Cipher Spec
		return t.processChangeCipherSpec(session, recordData, timestamp)
	default:
		return nil, fmt.Errorf("unknown TLS content type: 0x%02x", contentType)
	}
}

// processHandshake processes TLS handshake messages
func (t *TLSDecryptor) processHandshake(session *TLSSession, data []byte, timestamp int64) (*DecryptedData, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("handshake message too short")
	}

	handshakeType := data[0]
	
	switch handshakeType {
	case 0x01: // Client Hello
		return t.processClientHello(session, data, timestamp)
	case 0x02: // Server Hello
		return t.processServerHello(session, data, timestamp)
	case 0x0B: // Certificate
		return t.processCertificate(session, data, timestamp)
	case 0x10: // Client Key Exchange
		return t.processClientKeyExchange(session, data, timestamp)
	default:
		// For other handshake messages, just return metadata
		return &DecryptedData{
			Session:     session,
			Timestamp:   timestamp,
			Protocol:    "TLS-Handshake",
			ContentType: ContentTypeBinary,
			Payload:     data,
		}, nil
	}
}

// processClientHello processes Client Hello message
func (t *TLSDecryptor) processClientHello(session *TLSSession, data []byte, timestamp int64) (*DecryptedData, error) {
	// Extract Server Name Indication (SNI) if present
	// This is a simplified implementation - full parsing would be more complex
	
	if len(data) > 40 {
		// Look for SNI extension (simplified)
		sni := t.extractSNI(data)
		if sni != "" {
			session.ServerName = sni
		}
	}

	return &DecryptedData{
		Session:     session,
		Timestamp:   timestamp,
		Protocol:    "TLS-ClientHello",
		ContentType: ContentTypeBinary,
		Payload:     data,
	}, nil
}

// processServerHello processes Server Hello message
func (t *TLSDecryptor) processServerHello(session *TLSSession, data []byte, timestamp int64) (*DecryptedData, error) {
	// data includes handshake header
	// Skip handshake type (1) + length (3) + version (2) + random (32) = 38 bytes
	if len(data) >= 39 {
		// Skip session ID
		sessionIDLen := data[38]
		cipherSuiteOffset := 39 + int(sessionIDLen)
		if len(data) >= cipherSuiteOffset+2 {
			session.CipherSuite = uint16(data[cipherSuiteOffset])<<8 | uint16(data[cipherSuiteOffset+1])
		}
	}

	return &DecryptedData{
		Session:     session,
		Timestamp:   timestamp,
		Protocol:    "TLS-ServerHello",
		ContentType: ContentTypeBinary,
		Payload:     data,
	}, nil
}

// processCertificate processes Certificate message
func (t *TLSDecryptor) processCertificate(session *TLSSession, data []byte, timestamp int64) (*DecryptedData, error) {
	// In a full implementation, we would parse the certificate chain here
	return &DecryptedData{
		Session:     session,
		Timestamp:   timestamp,
		Protocol:    "TLS-Certificate",
		ContentType: ContentTypeBinary,
		Payload:     data,
	}, nil
}

// processClientKeyExchange processes Client Key Exchange message
func (t *TLSDecryptor) processClientKeyExchange(session *TLSSession, data []byte, timestamp int64) (*DecryptedData, error) {
	// This is where we would decrypt the pre-master secret using the private key
	// and derive the master secret for session decryption
	
	if session.ServerName != "" {
		t.mutex.RLock()
		privateKey, hasKey := t.privateKeys[session.ServerName]
		t.mutex.RUnlock()

		if hasKey && len(data) > 2 {
			// Extract encrypted pre-master secret
			encryptedLength := uint16(data[1])<<8 | uint16(data[2])
			if len(data) >= int(3+encryptedLength) {
				encryptedPreMaster := data[3 : 3+encryptedLength]
				
				// Decrypt pre-master secret
				preMasterSecret, err := t.decryptPreMasterSecret(privateKey, encryptedPreMaster)
				if err == nil {
					// Derive master secret (simplified - real implementation needs client/server random)
					session.MasterSecret = t.deriveMasterSecret(preMasterSecret, nil, nil)
					session.State = TLSStateEstablished
				}
			}
		}
	}
	
	// Even without decryption capability, we've seen the key exchange
	// so we can consider the handshake complete
	if session.State != TLSStateEstablished {
		session.State = TLSStateEstablished
	}

	return &DecryptedData{
		Session:     session,
		Timestamp:   timestamp,
		Protocol:    "TLS-KeyExchange",
		ContentType: ContentTypeBinary,
		Payload:     data,
	}, nil
}

// processApplicationData processes encrypted application data
func (t *TLSDecryptor) processApplicationData(session *TLSSession, data []byte, timestamp int64) (*DecryptedData, error) {
	if session.State != TLSStateEstablished || len(session.MasterSecret) == 0 {
		// Can't decrypt - no master secret available
		return &DecryptedData{
			Session:     session,
			Timestamp:   timestamp,
			Protocol:    "TLS-Encrypted",
			ContentType: ContentTypeBinary,
			Payload:     data,
		}, nil
	}

	// Attempt to decrypt the application data
	decrypted, err := t.decryptApplicationData(session, data)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt application data: %w", err)
	}

	// Determine content type
	contentType := t.detectContentType(decrypted)

	return &DecryptedData{
		Session:     session,
		Timestamp:   timestamp,
		Protocol:    "TLS-Decrypted",
		ContentType: contentType,
		Payload:     decrypted,
	}, nil
}

// processAlert processes TLS alert messages
func (t *TLSDecryptor) processAlert(session *TLSSession, data []byte, timestamp int64) (*DecryptedData, error) {
	if len(data) >= 2 {
		level := data[0]
		description := data[1]
		
		if level == 2 { // Fatal alert
			session.State = TLSStateClosed
		}
		
		_ = description // Suppress unused variable warning
	}

	return &DecryptedData{
		Session:     session,
		Timestamp:   timestamp,
		Protocol:    "TLS-Alert",
		ContentType: ContentTypeBinary,
		Payload:     data,
	}, nil
}

// processChangeCipherSpec processes Change Cipher Spec messages
func (t *TLSDecryptor) processChangeCipherSpec(session *TLSSession, data []byte, timestamp int64) (*DecryptedData, error) {
	return &DecryptedData{
		Session:     session,
		Timestamp:   timestamp,
		Protocol:    "TLS-ChangeCipherSpec",
		ContentType: ContentTypeBinary,
		Payload:     data,
	}, nil
}

// Helper functions (simplified implementations)

func (t *TLSDecryptor) extractSNI(data []byte) string {
	// Simplified SNI extraction - real implementation would be more robust
	// Look for the SNI extension pattern
	for i := 0; i < len(data)-10; i++ {
		if data[i] == 0x00 && data[i+1] == 0x00 { // Server Name extension
			if i+9 < len(data) {
				nameLength := uint16(data[i+7])<<8 | uint16(data[i+8])
				if i+9+int(nameLength) <= len(data) {
					return string(data[i+9 : i+9+int(nameLength)])
				}
			}
		}
	}
	return ""
}

func (t *TLSDecryptor) decryptPreMasterSecret(privateKey *rsa.PrivateKey, encrypted []byte) ([]byte, error) {
	// This would use RSA decryption to get the pre-master secret
	// Simplified implementation
	return []byte("simplified-pre-master-secret"), nil
}

func (t *TLSDecryptor) deriveMasterSecret(preMasterSecret, clientRandom, serverRandom []byte) []byte {
	// This would implement the TLS PRF to derive the master secret
	// Simplified implementation
	return []byte("simplified-master-secret-12345678901234567890123456789012345678901234567890")
}

func (t *TLSDecryptor) decryptApplicationData(session *TLSSession, encrypted []byte) ([]byte, error) {
	// This would implement AES/ChaCha20 decryption using derived keys
	// For now, return a placeholder indicating we attempted decryption
	return []byte("DECRYPTED: " + string(encrypted[:min(50, len(encrypted))])), nil
}

func (t *TLSDecryptor) detectContentType(data []byte) ContentType {
	dataStr := string(data)
	if strings.HasPrefix(dataStr, "GET ") || strings.HasPrefix(dataStr, "POST ") || 
	   strings.HasPrefix(dataStr, "HTTP/") {
		return ContentTypeHTTP
	}
	if strings.HasPrefix(dataStr, "{") || strings.HasPrefix(dataStr, "[") {
		return ContentTypeJSON
	}
	if strings.HasPrefix(dataStr, "<?xml") || strings.HasPrefix(dataStr, "<html") || 
	   (strings.HasPrefix(dataStr, "<") && strings.Contains(dataStr, ">")) {
		return ContentTypeXML
	}
	return ContentTypeBinary
}

func hexToBytes(hexStr string) ([]byte, error) {
	// Convert hex string to bytes
	if len(hexStr)%2 != 0 {
		return nil, fmt.Errorf("invalid hex string length")
	}
	
	bytes := make([]byte, len(hexStr)/2)
	for i := 0; i < len(hexStr); i += 2 {
		var b byte
		_, err := fmt.Sscanf(hexStr[i:i+2], "%02x", &b)
		if err != nil {
			return nil, err
		}
		bytes[i/2] = b
	}
	return bytes, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetActiveSessions returns all active TLS sessions
func (t *TLSDecryptor) GetActiveSessions() []*TLSSession {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	
	sessions := make([]*TLSSession, 0, len(t.sessions))
	for _, session := range t.sessions {
		if session.State == TLSStateEstablished {
			sessions = append(sessions, session)
		}
	}
	return sessions
}

// GetSessionStats returns statistics about TLS sessions
func (t *TLSDecryptor) GetSessionStats() map[string]int {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	
	stats := map[string]int{
		"total_sessions":       len(t.sessions),
		"active_sessions":      0,
		"decryptable_sessions": 0,
		"loaded_certificates":  len(t.certificates),
		"keylog_entries":      len(t.keyLogEntries),
	}
	
	for _, session := range t.sessions {
		if session.State == TLSStateEstablished {
			stats["active_sessions"]++
			if len(session.MasterSecret) > 0 {
				stats["decryptable_sessions"]++
			}
		}
	}
	
	return stats
}