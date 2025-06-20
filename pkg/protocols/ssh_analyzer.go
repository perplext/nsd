package protocols

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// SSHAnalyzer analyzes SSH protocol traffic
type SSHAnalyzer struct {
	BaseAnalyzer
	sessions map[string]*SSHSession
}

// SSHSession represents an active SSH session
type SSHSession struct {
	ID                string
	ClientIP          net.IP
	ServerIP          net.IP
	Port              uint16
	ClientVersion     string
	ServerVersion     string
	EncryptionAlg     string
	MACAlg           string
	CompressionAlg    string
	Username          string
	AuthMethod        string
	AuthAttempts      []AuthAttempt
	KeyExchanges      []KeyExchange
	ChannelRequests   []ChannelRequest
	StartTime         time.Time
	LastActivity      time.Time
	Authenticated     bool
	Encrypted         bool
	BytesTransferred  int64
	PacketsTransferred int64
	ClientFingerprint string
	ServerFingerprint string
	State             SSHState
}

// SSHState represents the state of an SSH connection
type SSHState int

const (
	SSHStateInit SSHState = iota
	SSHStateVersionExchange
	SSHStateKeyExchange
	SSHStateAuthentication
	SSHStateEstablished
	SSHStateTerminated
)

// AuthAttempt represents an SSH authentication attempt
type AuthAttempt struct {
	Username   string
	Method     string
	Success    bool
	Timestamp  time.Time
	PublicKey  string
	Error      string
}

// KeyExchange represents an SSH key exchange
type KeyExchange struct {
	Algorithm     string
	ClientKex     []byte
	ServerKex     []byte
	SharedSecret  []byte
	Timestamp     time.Time
}

// ChannelRequest represents an SSH channel request
type ChannelRequest struct {
	Type        string
	WantReply   bool
	Data        []byte
	Success     bool
	Timestamp   time.Time
}

// SSHMessage represents a parsed SSH protocol message
type SSHMessage struct {
	Type      byte
	Length    uint32
	Payload   []byte
	Raw       []byte
	Timestamp time.Time
}

// NewSSHAnalyzer creates a new SSH analyzer
func NewSSHAnalyzer() ProtocolAnalyzer {
	return &SSHAnalyzer{
		BaseAnalyzer: BaseAnalyzer{
			protocolName: "SSH",
			ports:        []uint16{22, 2222}, // Standard and alternative SSH ports
		},
		sessions: make(map[string]*SSHSession),
	}
}

// AnalyzeStream analyzes an SSH stream
func (ssh *SSHAnalyzer) AnalyzeStream(flow gopacket.Flow, reader *tcpreader.ReaderStream) []ProtocolEvent {
	var events []ProtocolEvent
	buf := bufio.NewReader(reader)
	
	// Create session key
	sessionKey := fmt.Sprintf("%s->%s", flow.Src().String(), flow.Dst().String())
	
	// Get or create session
	session := ssh.getOrCreateSession(sessionKey, flow)
	
	// Read SSH protocol data
	events = append(events, ssh.analyzeSSHStream(session, buf)...)
	
	return events
}

// IsProtocolTraffic determines if data is SSH traffic
func (ssh *SSHAnalyzer) IsProtocolTraffic(data []byte) bool {
	dataStr := string(data)
	
	// Check for SSH version string
	if strings.HasPrefix(dataStr, "SSH-2.0-") || strings.HasPrefix(dataStr, "SSH-1.") {
		return true
	}
	
	// Check for common SSH server banners
	sshBanners := []string{"OpenSSH", "libssh", "Cisco", "dropbear"}
	for _, banner := range sshBanners {
		if strings.Contains(dataStr, banner) {
			return true
		}
	}
	
	return false
}

func (ssh *SSHAnalyzer) getOrCreateSession(sessionKey string, flow gopacket.Flow) *SSHSession {
	if session, exists := ssh.sessions[sessionKey]; exists {
		session.LastActivity = time.Now()
		return session
	}
	
	session := &SSHSession{
		ID:                fmt.Sprintf("ssh_%d", time.Now().UnixNano()),
		ClientIP:          net.ParseIP(flow.Src().String()),
		ServerIP:          net.ParseIP(flow.Dst().String()),
		Port:              uint16(flow.Dst().FastHash()),
		AuthAttempts:      make([]AuthAttempt, 0),
		KeyExchanges:      make([]KeyExchange, 0),
		ChannelRequests:   make([]ChannelRequest, 0),
		StartTime:         time.Now(),
		LastActivity:      time.Now(),
		State:             SSHStateInit,
	}
	
	ssh.sessions[sessionKey] = session
	return session
}

func (ssh *SSHAnalyzer) analyzeSSHStream(session *SSHSession, reader *bufio.Reader) []ProtocolEvent {
	var events []ProtocolEvent
	
	switch session.State {
	case SSHStateInit, SSHStateVersionExchange:
		events = append(events, ssh.analyzeVersionExchange(session, reader)...)
	case SSHStateKeyExchange:
		events = append(events, ssh.analyzeKeyExchange(session, reader)...)
	case SSHStateAuthentication:
		events = append(events, ssh.analyzeAuthentication(session, reader)...)
	case SSHStateEstablished:
		events = append(events, ssh.analyzeEstablishedSession(session, reader)...)
	}
	
	return events
}

func (ssh *SSHAnalyzer) analyzeVersionExchange(session *SSHSession, reader *bufio.Reader) []ProtocolEvent {
	var events []ProtocolEvent
	
	// Read version strings
	for {
		line, err := ReadLine(reader)
		if err != nil {
			break
		}
		
		if strings.HasPrefix(line, "SSH-") {
			event := ProtocolEvent{
				ID:        GenerateEventID("SSH"),
				Protocol:  "SSH",
				EventType: EventTypeConnection,
				Data: map[string]interface{}{
					"session_id": session.ID,
					"version":    line,
				},
			}
			
			// Determine if this is client or server version
			if session.ClientVersion == "" {
				session.ClientVersion = line
				event.Data["role"] = "client"
				
				// Extract client information
				ssh.parseClientVersion(session, line)
			} else if session.ServerVersion == "" {
				session.ServerVersion = line
				event.Data["role"] = "server"
				
				// Extract server information
				ssh.parseServerVersion(session, line)
				
				// Version exchange complete, move to key exchange
				session.State = SSHStateKeyExchange
			}
			
			events = append(events, event)
		}
	}
	
	return events
}

func (ssh *SSHAnalyzer) analyzeKeyExchange(session *SSHSession, reader *bufio.Reader) []ProtocolEvent {
	var events []ProtocolEvent
	
	// Read SSH protocol messages
	for {
		msg, err := ssh.readSSHMessage(reader)
		if err != nil {
			break
		}
		
		event := ssh.processKeyExchangeMessage(session, msg)
		if event != nil {
			events = append(events, *event)
		}
	}
	
	return events
}

func (ssh *SSHAnalyzer) analyzeAuthentication(session *SSHSession, reader *bufio.Reader) []ProtocolEvent {
	var events []ProtocolEvent
	
	// Read SSH protocol messages during authentication phase
	for {
		msg, err := ssh.readSSHMessage(reader)
		if err != nil {
			break
		}
		
		event := ssh.processAuthMessage(session, msg)
		if event != nil {
			events = append(events, *event)
		}
	}
	
	return events
}

func (ssh *SSHAnalyzer) analyzeEstablishedSession(session *SSHSession, reader *bufio.Reader) []ProtocolEvent {
	var events []ProtocolEvent
	
	// Count encrypted data packets
	data := make([]byte, 4096)
	totalBytes := 0
	
	for {
		n, err := reader.Read(data)
		if err != nil {
			break
		}
		totalBytes += n
		session.BytesTransferred += int64(n)
		session.PacketsTransferred++
	}
	
	if totalBytes > 0 {
		event := ProtocolEvent{
			ID:        GenerateEventID("SSH"),
			Protocol:  "SSH",
			EventType: EventTypeDataTransfer,
			Data: map[string]interface{}{
				"session_id":      session.ID,
				"bytes":          totalBytes,
				"total_bytes":    session.BytesTransferred,
				"total_packets":  session.PacketsTransferred,
				"encrypted":      session.Encrypted,
			},
		}
		events = append(events, event)
	}
	
	return events
}

func (ssh *SSHAnalyzer) readSSHMessage(reader *bufio.Reader) (*SSHMessage, error) {
	// Read packet length (first 4 bytes)
	lengthBytes := make([]byte, 4)
	_, err := reader.Read(lengthBytes)
	if err != nil {
		return nil, err
	}
	
	length := binary.BigEndian.Uint32(lengthBytes)
	
	// Read padding length (1 byte)
	paddingLengthByte := make([]byte, 1)
	_, err = reader.Read(paddingLengthByte)
	if err != nil {
		return nil, err
	}
	
	paddingLength := paddingLengthByte[0]
	
	// Calculate payload length
	payloadLength := length - uint32(paddingLength) - 1
	
	// Read message type (1 byte)
	msgTypeByte := make([]byte, 1)
	_, err = reader.Read(msgTypeByte)
	if err != nil {
		return nil, err
	}
	
	msgType := msgTypeByte[0]
	
	// Read payload
	payload := make([]byte, payloadLength-1) // -1 for message type
	_, err = reader.Read(payload)
	if err != nil {
		return nil, err
	}
	
	// Read padding
	padding := make([]byte, paddingLength)
	_, err = reader.Read(padding)
	if err != nil {
		return nil, err
	}
	
	// Reconstruct full message
	fullMsg := append(lengthBytes, paddingLengthByte...)
	fullMsg = append(fullMsg, msgTypeByte...)
	fullMsg = append(fullMsg, payload...)
	fullMsg = append(fullMsg, padding...)
	
	return &SSHMessage{
		Type:      msgType,
		Length:    length,
		Payload:   payload,
		Raw:       fullMsg,
		Timestamp: time.Now(),
	}, nil
}

func (ssh *SSHAnalyzer) processKeyExchangeMessage(session *SSHSession, msg *SSHMessage) *ProtocolEvent {
	event := &ProtocolEvent{
		ID:        GenerateEventID("SSH"),
		Protocol:  "SSH",
		EventType: EventTypeCommand,
		Data: map[string]interface{}{
			"session_id":   session.ID,
			"message_type": msg.Type,
			"message_size": len(msg.Raw),
		},
	}
	
	switch msg.Type {
	case 20: // SSH_MSG_KEXINIT
		kex := ssh.parseKexInit(msg.Payload)
		if kex != nil {
			session.KeyExchanges = append(session.KeyExchanges, *kex)
			event.Data["kex_algorithms"] = kex.Algorithm
		}
		
	case 21: // SSH_MSG_NEWKEYS
		session.Encrypted = true
		session.State = SSHStateAuthentication
		event.Data["encryption_enabled"] = true
		
	case 30: // SSH_MSG_KEXDH_INIT
		event.Data["kex_dh_init"] = true
		
	case 31: // SSH_MSG_KEXDH_REPLY
		event.Data["kex_dh_reply"] = true
		
	default:
		event.Data["unknown_message"] = true
	}
	
	return event
}

func (ssh *SSHAnalyzer) processAuthMessage(session *SSHSession, msg *SSHMessage) *ProtocolEvent {
	event := &ProtocolEvent{
		ID:        GenerateEventID("SSH"),
		Protocol:  "SSH",
		EventType: EventTypeAuthentication,
		Data: map[string]interface{}{
			"session_id":   session.ID,
			"message_type": msg.Type,
		},
	}
	
	switch msg.Type {
	case 50: // SSH_MSG_USERAUTH_REQUEST
		auth := ssh.parseAuthRequest(msg.Payload)
		if auth != nil {
			session.AuthAttempts = append(session.AuthAttempts, *auth)
			event.Username = auth.Username
			event.Data["auth_method"] = auth.Method
		}
		
	case 51: // SSH_MSG_USERAUTH_FAILURE
		event.Data["auth_failed"] = true
		if len(session.AuthAttempts) > 0 {
			session.AuthAttempts[len(session.AuthAttempts)-1].Success = false
		}
		
	case 52: // SSH_MSG_USERAUTH_SUCCESS
		session.Authenticated = true
		session.State = SSHStateEstablished
		event.Data["auth_success"] = true
		if len(session.AuthAttempts) > 0 {
			session.AuthAttempts[len(session.AuthAttempts)-1].Success = true
			session.Username = session.AuthAttempts[len(session.AuthAttempts)-1].Username
			session.AuthMethod = session.AuthAttempts[len(session.AuthAttempts)-1].Method
		}
		
	case 53: // SSH_MSG_USERAUTH_BANNER
		banner := string(msg.Payload)
		event.Data["banner"] = banner
		
	default:
		event.Data["unknown_auth_message"] = true
	}
	
	return event
}

func (ssh *SSHAnalyzer) parseClientVersion(session *SSHSession, version string) {
	// Extract client fingerprint from version string
	session.ClientFingerprint = ssh.calculateFingerprint(version)
}

func (ssh *SSHAnalyzer) parseServerVersion(session *SSHSession, version string) {
	// Extract server fingerprint from version string
	session.ServerFingerprint = ssh.calculateFingerprint(version)
}

func (ssh *SSHAnalyzer) calculateFingerprint(data string) string {
	hash := md5.Sum([]byte(data))
	return fmt.Sprintf("%x", hash)
}

func (ssh *SSHAnalyzer) parseKexInit(payload []byte) *KeyExchange {
	if len(payload) < 16 {
		return nil
	}
	
	// Skip random bytes (16 bytes)
	// pos := 16
	
	// Read algorithm name lists (simplified parsing)
	kex := &KeyExchange{
		Timestamp: time.Now(),
	}
	
	// In a full implementation, would parse all algorithm lists
	// For now, just mark that key exchange is happening
	kex.Algorithm = "diffie-hellman-group14-sha256" // Default assumption
	
	return kex
}

func (ssh *SSHAnalyzer) parseAuthRequest(payload []byte) *AuthAttempt {
	if len(payload) < 4 {
		return nil
	}
	
	reader := bytes.NewReader(payload)
	
	// Read username length
	var usernameLen uint32
	binary.Read(reader, binary.BigEndian, &usernameLen)
	
	// Read username
	username := make([]byte, usernameLen)
	reader.Read(username)
	
	// Read service name length
	var serviceLen uint32
	binary.Read(reader, binary.BigEndian, &serviceLen)
	
	// Skip service name
	reader.Seek(int64(serviceLen), 1)
	
	// Read method name length
	var methodLen uint32
	binary.Read(reader, binary.BigEndian, &methodLen)
	
	// Read method name
	method := make([]byte, methodLen)
	reader.Read(method)
	
	return &AuthAttempt{
		Username:  string(username),
		Method:    string(method),
		Timestamp: time.Now(),
	}
}

// GetActiveSessions returns all active SSH sessions
func (ssh *SSHAnalyzer) GetActiveSessions() []*SSHSession {
	var sessions []*SSHSession
	cutoff := time.Now().Add(-30 * time.Minute)
	
	for key, session := range ssh.sessions {
		if session.LastActivity.After(cutoff) {
			sessions = append(sessions, session)
		} else {
			delete(ssh.sessions, key)
		}
	}
	
	return sessions
}

// GetSessionStats returns SSH session statistics
func (ssh *SSHAnalyzer) GetSessionStats() map[string]interface{} {
	activeSessions := ssh.GetActiveSessions()
	
	stats := map[string]interface{}{
		"active_sessions":        len(activeSessions),
		"authenticated_sessions": 0,
		"failed_auth_attempts":   0,
		"successful_auths":       0,
		"total_bytes":           int64(0),
		"encrypted_sessions":     0,
	}
	
	for _, session := range activeSessions {
		if session.Authenticated {
			stats["authenticated_sessions"] = stats["authenticated_sessions"].(int) + 1
		}
		
		if session.Encrypted {
			stats["encrypted_sessions"] = stats["encrypted_sessions"].(int) + 1
		}
		
		stats["total_bytes"] = stats["total_bytes"].(int64) + session.BytesTransferred
		
		for _, auth := range session.AuthAttempts {
			if auth.Success {
				stats["successful_auths"] = stats["successful_auths"].(int) + 1
			} else {
				stats["failed_auth_attempts"] = stats["failed_auth_attempts"].(int) + 1
			}
		}
	}
	
	return stats
}

// DetectBruteForce detects SSH brute force attempts
func (ssh *SSHAnalyzer) DetectBruteForce() []ProtocolEvent {
	var events []ProtocolEvent
	threshold := 5 // Failed attempts threshold
	timeWindow := 5 * time.Minute
	
	// Group failed attempts by client IP
	failedAttempts := make(map[string][]AuthAttempt)
	
	for _, session := range ssh.sessions {
		clientIP := session.ClientIP.String()
		for _, auth := range session.AuthAttempts {
			if !auth.Success && time.Since(auth.Timestamp) < timeWindow {
				failedAttempts[clientIP] = append(failedAttempts[clientIP], auth)
			}
		}
	}
	
	// Check for brute force patterns
	for ip, attempts := range failedAttempts {
		if len(attempts) >= threshold {
			event := ProtocolEvent{
				ID:        GenerateEventID("SSH"),
				Protocol:  "SSH",
				EventType: EventTypeError,
				SourceIP:  net.ParseIP(ip),
				Command:   "BRUTE_FORCE_DETECTED",
				Data: map[string]interface{}{
					"client_ip":       ip,
					"failed_attempts": len(attempts),
					"time_window":     timeWindow.String(),
					"usernames":       ssh.extractUsernames(attempts),
				},
			}
			events = append(events, event)
		}
	}
	
	return events
}

func (ssh *SSHAnalyzer) extractUsernames(attempts []AuthAttempt) []string {
	usernames := make(map[string]bool)
	for _, attempt := range attempts {
		usernames[attempt.Username] = true
	}
	
	var result []string
	for username := range usernames {
		result = append(result, username)
	}
	
	return result
}