package protocols

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type SCPAnalyzer struct {
	sessions map[string]*SCPSession
}

type SCPSession struct {
	ID              string
	ClientIP        net.IP
	ServerIP        net.IP
	ClientPort      uint16
	ServerPort      uint16
	State           string
	Command         string
	Direction       string // "upload" or "download"
	Filename        string
	FileSize        int64
	FileMode        string
	BytesTransferred int64
	StartTime       time.Time
	LastActivity    time.Time
	Complete        bool
	Error           string
	Files           []SCPFile
	Recursive       bool
	PreserveTimes   bool
	SourcePath      string
	TargetPath      string
}

type SCPFile struct {
	Name         string
	Size         int64
	Mode         string
	Timestamp    time.Time
	BytesTransferred int64
	Complete     bool
}

const (
	SCP_STATE_INIT       = "init"
	SCP_STATE_HANDSHAKE  = "handshake"
	SCP_STATE_AUTH       = "auth"
	SCP_STATE_COMMAND    = "command"
	SCP_STATE_TRANSFER   = "transfer"
	SCP_STATE_COMPLETE   = "complete"
	SCP_STATE_ERROR      = "error"
)

func NewSCPAnalyzer() *SCPAnalyzer {
	return &SCPAnalyzer{
		sessions: make(map[string]*SCPSession),
	}
}

func (scp *SCPAnalyzer) GetProtocol() string {
	return "SCP"
}

func (scp *SCPAnalyzer) GetPort() uint16 {
	return 22 // SCP runs over SSH
}

func (scp *SCPAnalyzer) ProcessPacket(packet gopacket.Packet) *ProtocolEvent {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}

	tcp := tcpLayer.(*layers.TCP)
	
	// SCP runs over SSH (port 22)
	if tcp.DstPort != 22 && tcp.SrcPort != 22 {
		return nil
	}

	payload := tcp.Payload
	if len(payload) == 0 {
		return nil
	}

	sessionID := scp.getSessionID(packet)
	session := scp.getOrCreateSession(sessionID, packet)

	return scp.processSSHPayload(session, payload, packet)
}

func (scp *SCPAnalyzer) processSSHPayload(session *SCPSession, payload []byte, packet gopacket.Packet) *ProtocolEvent {
	// Since SCP runs over SSH, we need to detect SCP patterns in encrypted traffic
	// We look for SSH protocol patterns and SCP command patterns
	
	data := string(payload)
	
	// Look for SSH version exchange
	if strings.HasPrefix(data, "SSH-") {
		session.State = SCP_STATE_HANDSHAKE
		return &ProtocolEvent{
			Protocol:    "SCP",
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

	// Look for SCP command patterns (these appear during SSH channel establishment)
	if scp.detectSCPCommand(data, session) {
		return scp.createSCPCommandEvent(session)
	}

	// Look for SCP protocol messages (C mode size filename, T mtime mtime atime atime)
	if event := scp.parseSCPProtocol(session, data); event != nil {
		return event
	}

	// Monitor data transfer patterns
	if session.State == SCP_STATE_TRANSFER {
		return scp.processDataTransfer(session, len(payload))
	}

	return nil
}

func (scp *SCPAnalyzer) detectSCPCommand(data string, session *SCPSession) bool {
	// Look for common SCP command patterns
	scpPatterns := []string{
		"scp -t",      // SCP sink mode (receiving files)
		"scp -f",      // SCP source mode (sending files)
		"scp -r",      // Recursive SCP
		"scp -p",      // Preserve timestamps
		"scp -v",      // Verbose mode
	}

	for _, pattern := range scpPatterns {
		if strings.Contains(data, pattern) {
			session.Command = pattern
			session.State = SCP_STATE_COMMAND
			
			// Determine direction based on flags
			if strings.Contains(pattern, "-t") {
				session.Direction = "upload"
			} else if strings.Contains(pattern, "-f") {
				session.Direction = "download"
			}
			
			return true
		}
	}

	// Look for file paths in commands
	filePathPattern := regexp.MustCompile(`[/\w\.-]+\.(txt|pdf|doc|zip|tar|gz|jpg|png|mp4|avi|mov|mp3|wav|exe|bin|so|dll|conf|log|csv|json|xml|html|css|js|py|go|java|cpp|c|h)`)
	if matches := filePathPattern.FindStringSubmatch(data); len(matches) > 0 {
		session.Filename = matches[0]
		return true
	}

	return false
}

func (scp *SCPAnalyzer) parseSCPProtocol(session *SCPSession, data string) *ProtocolEvent {
	// SCP protocol messages:
	// C<mode> <size> <filename> - Copy file
	// D<mode> <size> <dirname>  - Directory
	// T<mtime> 0 <atime> 0     - Timestamp
	// E                        - End directory
	
	lines := strings.Split(data, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Copy file command
		if strings.HasPrefix(line, "C") && len(line) > 1 {
			parts := strings.Fields(line[1:])
			if len(parts) >= 3 {
				mode := parts[0]
				size, _ := strconv.ParseInt(parts[1], 10, 64)
				filename := parts[2]
				
				file := SCPFile{
					Name:      filename,
					Size:      size,
					Mode:      mode,
					Timestamp: time.Now(),
				}
				
				session.Files = append(session.Files, file)
				session.Filename = filename
				session.FileSize = size
				session.FileMode = mode
				session.State = SCP_STATE_TRANSFER
				
				return &ProtocolEvent{
					Protocol:    "SCP",
					EventType:   EventTypeFileTransfer,
					Timestamp:   time.Now(),
					SourceIP:    session.ClientIP,
					DestIP:      session.ServerIP,
					SourcePort:  session.ClientPort,
					DestPort:    session.ServerPort,
					Filename:    filename,
					FileSize:    size,
					Data: map[string]interface{}{
						"session_id": session.ID,
						"filename":   filename,
						"size":       size,
						"mode":       mode,
						"direction":  session.Direction,
					},
				}
			}
		}
		
		// Directory command
		if strings.HasPrefix(line, "D") && len(line) > 1 {
			parts := strings.Fields(line[1:])
			if len(parts) >= 3 {
				dirname := parts[2]
				return &ProtocolEvent{
					Protocol:    "SCP",
					EventType:   EventTypeDataTransfer,
					Timestamp:   time.Now(),
					SourceIP:    session.ClientIP,
					DestIP:      session.ServerIP,
					SourcePort:  session.ClientPort,
					DestPort:    session.ServerPort,
					Data: map[string]interface{}{
						"session_id": session.ID,
						"directory":  dirname,
						"direction":  session.Direction,
					},
				}
			}
		}
		
		// Timestamp command
		if strings.HasPrefix(line, "T") {
			return &ProtocolEvent{
				Protocol:    "SCP",
				EventType:   EventTypeDataTransfer,
				Timestamp:   time.Now(),
				SourceIP:    session.ClientIP,
				DestIP:      session.ServerIP,
				SourcePort:  session.ClientPort,
				DestPort:    session.ServerPort,
				Data: map[string]interface{}{
					"session_id": session.ID,
					"type": "timestamp_preservation",
				},
			}
		}
	}
	
	return nil
}

func (scp *SCPAnalyzer) processDataTransfer(session *SCPSession, dataSize int) *ProtocolEvent {
	session.BytesTransferred += int64(dataSize)
	
	// Check if file transfer is complete
	if len(session.Files) > 0 {
		currentFile := &session.Files[len(session.Files)-1]
		currentFile.BytesTransferred += int64(dataSize)
		
		if currentFile.BytesTransferred >= currentFile.Size {
			currentFile.Complete = true
			session.State = SCP_STATE_COMPLETE
			
			return &ProtocolEvent{
				Protocol:    "SCP",
				EventType:   EventTypeFileTransfer,
				Timestamp:   time.Now(),
				SourceIP:    session.ClientIP,
				DestIP:      session.ServerIP,
				SourcePort:  session.ClientPort,
				DestPort:    session.ServerPort,
				Filename:    currentFile.Name,
				FileSize:    currentFile.Size,
				Direction:   DirectionUpload,
				Data: map[string]interface{}{
					"session_id":        session.ID,
					"filename":          currentFile.Name,
					"size":              currentFile.Size,
					"bytes_transferred": currentFile.BytesTransferred,
					"direction":         session.Direction,
					"duration":          time.Since(session.StartTime),
					"extracted_file": map[string]interface{}{
						"filename":    currentFile.Name,
						"size":        currentFile.Size,
						"protocol":    "SCP",
						"direction":   session.Direction,
						"client_ip":   session.ClientIP.String(),
						"server_ip":   session.ServerIP.String(),
						"start_time":  session.StartTime,
						"duration":    time.Since(session.StartTime),
					},
				},
			}
		}
	}
	
	return nil
}

func (scp *SCPAnalyzer) createSCPCommandEvent(session *SCPSession) *ProtocolEvent {
	direction := "download"
	if session.Direction == "upload" {
		direction = "upload"
	}
	
	return &ProtocolEvent{
		Protocol:    "SCP",
		EventType:   EventTypeCommand,
		Timestamp:   time.Now(),
		SourceIP:    session.ClientIP,
		DestIP:      session.ServerIP,
		SourcePort:  session.ClientPort,
		DestPort:    session.ServerPort,
		Command:     session.Command,
		Data: map[string]interface{}{
			"session_id": session.ID,
			"direction": direction,
			"recursive": session.Recursive,
			"preserve_times": session.PreserveTimes,
			"source_path": session.SourcePath,
			"target_path": session.TargetPath,
		},
	}
}

func (scp *SCPAnalyzer) getSessionID(packet gopacket.Packet) string {
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

func (scp *SCPAnalyzer) getOrCreateSession(sessionID string, packet gopacket.Packet) *SCPSession {
	if session, exists := scp.sessions[sessionID]; exists {
		session.LastActivity = time.Now()
		return session
	}

	netLayer := packet.NetworkLayer()
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	tcp := tcpLayer.(*layers.TCP)

	session := &SCPSession{
		ID:           sessionID,
		ClientIP:     net.ParseIP(netLayer.NetworkFlow().Src().String()),
		ServerIP:     net.ParseIP(netLayer.NetworkFlow().Dst().String()),
		ClientPort:   uint16(tcp.SrcPort),
		ServerPort:   uint16(tcp.DstPort),
		State:        SCP_STATE_INIT,
		StartTime:    time.Now(),
		LastActivity: time.Now(),
		Files:        make([]SCPFile, 0),
	}

	scp.sessions[sessionID] = session
	return session
}

func (scp *SCPAnalyzer) GetSessions() map[string]interface{} {
	sessions := make(map[string]interface{})
	for id, session := range scp.sessions {
		sessions[id] = map[string]interface{}{
			"client_ip":         session.ClientIP.String(),
			"server_ip":         session.ServerIP.String(),
			"state":             session.State,
			"command":           session.Command,
			"direction":         session.Direction,
			"files_count":       len(session.Files),
			"bytes_transferred": session.BytesTransferred,
			"start_time":        session.StartTime,
			"duration":          time.Since(session.StartTime),
		}
	}
	return sessions
}

func (scp *SCPAnalyzer) CleanupSessions() {
	cutoff := time.Now().Add(-10 * time.Minute)
	for id, session := range scp.sessions {
		if session.LastActivity.Before(cutoff) || session.Complete {
			delete(scp.sessions, id)
		}
	}
}