package protocols

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

type SFTPAnalyzer struct {
	sessions map[string]*SFTPSession
}

type SFTPSession struct {
	ID              string
	ClientIP        net.IP
	ServerIP        net.IP
	ClientPort      uint16
	ServerPort      uint16
	State           string
	Version         string
	Operations      []SFTPOperation
	BytesTransferred int64
	StartTime       time.Time
	LastActivity    time.Time
	Complete        bool
	Error           string
}

type SFTPOperation struct {
	Type      string // "open", "read", "write", "close", "stat", "mkdir", etc.
	Path      string
	Handle    string
	Size      int64
	Timestamp time.Time
	Complete  bool
}

const (
	SFTP_STATE_INIT      = "init"
	SFTP_STATE_VERSION   = "version"
	SFTP_STATE_ACTIVE    = "active"
	SFTP_STATE_COMPLETE  = "complete"
	SFTP_STATE_ERROR     = "error"
	
	// SFTP message types
	SSH_FXP_INIT        = 1
	SSH_FXP_VERSION     = 2
	SSH_FXP_OPEN        = 3
	SSH_FXP_CLOSE       = 4
	SSH_FXP_READ        = 5
	SSH_FXP_WRITE       = 6
	SSH_FXP_LSTAT       = 7
	SSH_FXP_FSTAT       = 8
	SSH_FXP_SETSTAT     = 9
	SSH_FXP_FSETSTAT    = 10
	SSH_FXP_OPENDIR     = 11
	SSH_FXP_READDIR     = 12
	SSH_FXP_REMOVE      = 13
	SSH_FXP_MKDIR       = 14
	SSH_FXP_RMDIR       = 15
	SSH_FXP_REALPATH    = 16
	SSH_FXP_STAT        = 17
	SSH_FXP_RENAME      = 18
	SSH_FXP_READLINK    = 19
	SSH_FXP_SYMLINK     = 20
	SSH_FXP_STATUS      = 101
	SSH_FXP_HANDLE      = 102
	SSH_FXP_DATA        = 103
	SSH_FXP_NAME        = 104
	SSH_FXP_ATTRS       = 105
)

func NewSFTPAnalyzer() *SFTPAnalyzer {
	return &SFTPAnalyzer{
		sessions: make(map[string]*SFTPSession),
	}
}

// GetProtocolName returns the protocol name
func (sftp *SFTPAnalyzer) GetProtocolName() string {
	return "SFTP"
}

// GetPorts returns the standard ports
func (sftp *SFTPAnalyzer) GetPorts() []uint16 {
	return []uint16{22} // SFTP runs over SSH
}

// AnalyzeStream analyzes a TCP stream for SFTP
func (sftp *SFTPAnalyzer) AnalyzeStream(flow gopacket.Flow, reader *tcpreader.ReaderStream) []ProtocolEvent {
	// SFTP analysis would go here
	// For now, return empty events
	return []ProtocolEvent{}
}

// IsProtocolTraffic determines if this is SFTP traffic
func (sftp *SFTPAnalyzer) IsProtocolTraffic(data []byte) bool {
	// Check for SSH banner or SFTP patterns
	if len(data) > 4 && strings.HasPrefix(string(data), "SSH-") {
		return true
	}
	// Check for SFTP message format
	if len(data) >= 5 {
		msgType := data[4]
		return msgType >= SSH_FXP_INIT && msgType <= SSH_FXP_ATTRS
	}
	return false
}

func (sftp *SFTPAnalyzer) ProcessPacket(packet gopacket.Packet) *ProtocolEvent {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}

	tcp := tcpLayer.(*layers.TCP)
	
	// SFTP runs over SSH (port 22)
	if tcp.DstPort != 22 && tcp.SrcPort != 22 {
		return nil
	}

	payload := tcp.Payload
	if len(payload) == 0 {
		return nil
	}

	sessionID := sftp.getSessionID(packet)
	session := sftp.getOrCreateSession(sessionID, packet)

	return sftp.processSSHPayload(session, payload, packet)
}

func (sftp *SFTPAnalyzer) processSSHPayload(session *SFTPSession, payload []byte, packet gopacket.Packet) *ProtocolEvent {
	// SFTP runs over SSH, so we need to detect SFTP patterns
	data := string(payload)
	
	// Look for SSH version exchange
	if strings.HasPrefix(data, "SSH-") {
		session.State = SFTP_STATE_INIT
		return &ProtocolEvent{
			Protocol:    "SFTP",
			EventType:   EventTypeConnection,
			Timestamp:   time.Now(),
			SourceIP:    session.ClientIP,
			DestIP:      session.ServerIP,
			SourcePort:  session.ClientPort,
			DestPort:    session.ServerPort,
			Data: map[string]interface{}{
				"session_id": session.ID,
				"ssh_version": strings.TrimSpace(data),
			},
		}
	}

	// Look for SFTP subsystem request
	if strings.Contains(data, "sftp") && strings.Contains(data, "subsystem") {
		session.State = SFTP_STATE_VERSION
		return &ProtocolEvent{
			Protocol:    "SFTP",
			EventType:   EventTypeCommand,
			Timestamp:   time.Now(),
			SourceIP:    session.ClientIP,
			DestIP:      session.ServerIP,
			SourcePort:  session.ClientPort,
			DestPort:    session.ServerPort,
			Command:     "sftp subsystem",
			Data: map[string]interface{}{
				"session_id": session.ID,
			},
		}
	}

	// Try to parse SFTP protocol messages
	if session.State == SFTP_STATE_INIT {
		return nil
	}

	return sftp.parseSFTPMessage(session, payload)
}

func (sftp *SFTPAnalyzer) parseSFTPMessage(session *SFTPSession, payload []byte) *ProtocolEvent {
	if len(payload) < 5 {
		return nil
	}

	// SFTP message format: length(4) + type(1) + data
	msgType := uint8(payload[4])
	
	event := &ProtocolEvent{
		Protocol:  "SFTP",
		Timestamp: time.Now(),
		SourceIP:  session.ClientIP,
		DestIP:    session.ServerIP,
		SourcePort: session.ClientPort,
		DestPort:  session.ServerPort,
		Data:      make(map[string]interface{}),
	}

	switch msgType {
	case SSH_FXP_INIT:
		session.State = SFTP_STATE_VERSION
		event.EventType = EventTypeConnection
		event.Data["type"] = "sftp_init"

	case SSH_FXP_VERSION:
		session.State = SFTP_STATE_ACTIVE
		if len(payload) >= 9 {
			version := uint32(payload[5])<<24 | uint32(payload[6])<<16 | uint32(payload[7])<<8 | uint32(payload[8])
			session.Version = fmt.Sprintf("%d", version)
			event.Data["version"] = version
		}
		event.EventType = EventTypeConnection
		event.Data["type"] = "sftp_version"

	case SSH_FXP_OPEN:
		path := sftp.extractStringFromPayload(payload, 9)
		operation := SFTPOperation{
			Type:      "open",
			Path:      path,
			Timestamp: time.Now(),
		}
		session.Operations = append(session.Operations, operation)
		event.EventType = EventTypeFileTransfer
		event.Filename = path
		event.Data["path"] = path
		event.Data["operation"] = "open"

	case SSH_FXP_CLOSE:
		handle := sftp.extractStringFromPayload(payload, 9)
		sftp.updateOperationByHandle(session, handle, "close")
		event.EventType = EventTypeFileTransfer
		event.Data["handle"] = handle
		event.Data["operation"] = "close"

	case SSH_FXP_READ:
		handle := sftp.extractStringFromPayload(payload, 9)
		event.EventType = EventTypeDataTransfer
		event.Data["handle"] = handle
		event.Data["operation"] = "read"

	case SSH_FXP_WRITE:
		handle := sftp.extractStringFromPayload(payload, 9)
		session.BytesTransferred += int64(len(payload) - 20) // Approximate data size
		event.EventType = EventTypeDataTransfer
		event.Data["handle"] = handle
		event.Data["data_size"] = len(payload) - 20
		event.Data["operation"] = "write"

	case SSH_FXP_MKDIR:
		path := sftp.extractStringFromPayload(payload, 9)
		operation := SFTPOperation{
			Type:      "mkdir",
			Path:      path,
			Timestamp: time.Now(),
		}
		session.Operations = append(session.Operations, operation)
		event.EventType = EventTypeCommand
		event.Command = fmt.Sprintf("mkdir %s", path)
		event.Data["path"] = path

	case SSH_FXP_REMOVE:
		path := sftp.extractStringFromPayload(payload, 9)
		operation := SFTPOperation{
			Type:      "remove",
			Path:      path,
			Timestamp: time.Now(),
		}
		session.Operations = append(session.Operations, operation)
		event.EventType = EventTypeCommand
		event.Command = fmt.Sprintf("remove %s", path)
		event.Data["path"] = path

	case SSH_FXP_RMDIR:
		path := sftp.extractStringFromPayload(payload, 9)
		operation := SFTPOperation{
			Type:      "rmdir",
			Path:      path,
			Timestamp: time.Now(),
		}
		session.Operations = append(session.Operations, operation)
		event.EventType = EventTypeCommand
		event.Command = fmt.Sprintf("rmdir %s", path)
		event.Data["path"] = path

	case SSH_FXP_RENAME:
		oldPath := sftp.extractStringFromPayload(payload, 9)
		// Extract new path (would need more complex parsing)
		operation := SFTPOperation{
			Type:      "rename",
			Path:      oldPath,
			Timestamp: time.Now(),
		}
		session.Operations = append(session.Operations, operation)
		event.EventType = EventTypeCommand
		event.Command = fmt.Sprintf("rename %s", oldPath)
		event.Data["old_path"] = oldPath

	case SSH_FXP_STAT, SSH_FXP_LSTAT, SSH_FXP_FSTAT:
		path := sftp.extractStringFromPayload(payload, 9)
		event.EventType = EventTypeCommand
		event.Command = fmt.Sprintf("stat %s", path)
		event.Data["path"] = path

	case SSH_FXP_STATUS:
		event.EventType = EventTypeDataTransfer
		event.Data["type"] = "status"

	case SSH_FXP_HANDLE:
		handle := sftp.extractStringFromPayload(payload, 9)
		event.EventType = EventTypeDataTransfer
		event.Data["handle"] = handle
		event.Data["type"] = "handle"

	case SSH_FXP_DATA:
		dataSize := len(payload) - 9
		session.BytesTransferred += int64(dataSize)
		event.EventType = EventTypeDataTransfer
		event.Data["data_size"] = dataSize

	case SSH_FXP_NAME:
		event.EventType = EventTypeDataTransfer
		event.Data["type"] = "name"

	default:
		return nil
	}

	// Add common details
	event.Data["session_id"] = session.ID
	event.Data["message_type"] = msgType
	event.Data["bytes_transferred"] = session.BytesTransferred
	event.Data["operations_count"] = len(session.Operations)

	// Check for file transfer completion
	if sftp.isFileTransferComplete(session) {
		event.Data["extracted_file"] = sftp.createFileTransferSummary(session)
	}

	return event
}

func (sftp *SFTPAnalyzer) extractStringFromPayload(payload []byte, offset int) string {
	if len(payload) < offset+4 {
		return ""
	}
	
	// Read string length (4 bytes)
	length := uint32(payload[offset])<<24 | uint32(payload[offset+1])<<16 | 
		uint32(payload[offset+2])<<8 | uint32(payload[offset+3])
	
	if len(payload) < offset+4+int(length) {
		return ""
	}
	
	return string(payload[offset+4 : offset+4+int(length)])
}

func (sftp *SFTPAnalyzer) updateOperationByHandle(session *SFTPSession, handle string, opType string) {
	for i := range session.Operations {
		if session.Operations[i].Handle == handle && !session.Operations[i].Complete {
			session.Operations[i].Complete = true
			break
		}
	}
}

func (sftp *SFTPAnalyzer) isFileTransferComplete(session *SFTPSession) bool {
	// Simple heuristic: if we have open and close operations
	hasOpen := false
	hasClose := false
	
	for _, op := range session.Operations {
		if op.Type == "open" {
			hasOpen = true
		}
		if op.Type == "close" {
			hasClose = true
		}
	}
	
	return hasOpen && hasClose && session.BytesTransferred > 0
}

func (sftp *SFTPAnalyzer) createFileTransferSummary(session *SFTPSession) map[string]interface{} {
	var filename string
	for _, op := range session.Operations {
		if op.Type == "open" && op.Path != "" {
			filename = op.Path
			break
		}
	}
	
	return map[string]interface{}{
		"filename":         filename,
		"bytes_transferred": session.BytesTransferred,
		"protocol":         "SFTP",
		"client_ip":        session.ClientIP.String(),
		"server_ip":        session.ServerIP.String(),
		"start_time":       session.StartTime,
		"duration":         time.Since(session.StartTime),
		"operations":       len(session.Operations),
	}
}

func (sftp *SFTPAnalyzer) getSessionID(packet gopacket.Packet) string {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return ""
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return ""
	}

	tcp := tcpLayer.(*layers.TCP)
	src := netLayer.NetworkFlow().Src().String()
	dst := netLayer.NetworkFlow().Dst().String()
	
	return fmt.Sprintf("%s:%d-%s:%d", src, tcp.SrcPort, dst, tcp.DstPort)
}

func (sftp *SFTPAnalyzer) getOrCreateSession(sessionID string, packet gopacket.Packet) *SFTPSession {
	if session, exists := sftp.sessions[sessionID]; exists {
		session.LastActivity = time.Now()
		return session
	}

	netLayer := packet.NetworkLayer()
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	tcp := tcpLayer.(*layers.TCP)

	session := &SFTPSession{
		ID:           sessionID,
		ClientIP:     net.ParseIP(netLayer.NetworkFlow().Src().String()),
		ServerIP:     net.ParseIP(netLayer.NetworkFlow().Dst().String()),
		ClientPort:   uint16(tcp.SrcPort),
		ServerPort:   uint16(tcp.DstPort),
		State:        SFTP_STATE_INIT,
		StartTime:    time.Now(),
		LastActivity: time.Now(),
		Operations:   make([]SFTPOperation, 0),
	}

	sftp.sessions[sessionID] = session
	return session
}

func (sftp *SFTPAnalyzer) GetSessions() map[string]interface{} {
	sessions := make(map[string]interface{})
	for id, session := range sftp.sessions {
		sessions[id] = map[string]interface{}{
			"client_ip":         session.ClientIP.String(),
			"server_ip":         session.ServerIP.String(),
			"state":             session.State,
			"version":           session.Version,
			"operations_count":  len(session.Operations),
			"bytes_transferred": session.BytesTransferred,
			"start_time":        session.StartTime,
			"duration":          time.Since(session.StartTime),
		}
	}
	return sessions
}

func (sftp *SFTPAnalyzer) CleanupSessions() {
	cutoff := time.Now().Add(-10 * time.Minute)
	for id, session := range sftp.sessions {
		if session.LastActivity.Before(cutoff) || session.Complete {
			delete(sftp.sessions, id)
		}
	}
}