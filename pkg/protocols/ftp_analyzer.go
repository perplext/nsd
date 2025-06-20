package protocols

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// FTPAnalyzer analyzes FTP protocol traffic
type FTPAnalyzer struct {
	BaseAnalyzer
	sessions map[string]*FTPSession
}

// FTPSession represents an active FTP session
type FTPSession struct {
	ID              string
	ClientIP        net.IP
	ServerIP        net.IP
	ControlPort     uint16
	DataPort        uint16
	Username        string
	CurrentDir      string
	TransferMode    string
	TransferType    string
	PassiveMode     bool
	DataConnection  *net.TCPAddr
	Commands        []FTPCommand
	Transfers       []FileTransfer
	StartTime       time.Time
	LastActivity    time.Time
	Authenticated   bool
}

// FTPCommand represents an FTP command
type FTPCommand struct {
	Command   string
	Arguments string
	Response  string
	Code      int
	Timestamp time.Time
}

// FileTransfer represents an FTP file transfer
type FileTransfer struct {
	Filename    string
	Direction   TransferDirection
	Size        int64
	StartTime   time.Time
	EndTime     time.Time
	Complete    bool
	Mode        string
	Type        string
}

// NewFTPAnalyzer creates a new FTP analyzer
func NewFTPAnalyzer() ProtocolAnalyzer {
	return &FTPAnalyzer{
		BaseAnalyzer: BaseAnalyzer{
			protocolName: "FTP",
			ports:        []uint16{21, 20}, // Control and data ports
		},
		sessions: make(map[string]*FTPSession),
	}
}

// AnalyzeStream analyzes an FTP stream
func (ftp *FTPAnalyzer) AnalyzeStream(flow gopacket.Flow, reader *tcpreader.ReaderStream) []ProtocolEvent {
	var events []ProtocolEvent
	buf := bufio.NewReader(reader)
	
	// Create session key
	sessionKey := fmt.Sprintf("%s->%s", flow.Src().String(), flow.Dst().String())
	
	// Get or create session
	session := ftp.getOrCreateSession(sessionKey, flow)
	
	// Determine if this is control or data channel
	srcPort := uint16(flow.Src().FastHash())
	dstPort := uint16(flow.Dst().FastHash())
	
	if srcPort == 21 || dstPort == 21 {
		// Control channel
		events = append(events, ftp.analyzeControlChannel(session, buf)...)
	} else {
		// Data channel
		events = append(events, ftp.analyzeDataChannel(session, buf)...)
	}
	
	return events
}

// IsProtocolTraffic determines if data is FTP traffic
func (ftp *FTPAnalyzer) IsProtocolTraffic(data []byte) bool {
	dataStr := strings.ToUpper(string(data))
	
	// Check for FTP server welcome messages
	if strings.HasPrefix(dataStr, "220 ") {
		return true
	}
	
	// Check for common FTP commands
	ftpCommands := []string{"USER ", "PASS ", "STOR ", "RETR ", "LIST ", "NLST ", "PWD", "CWD ", "TYPE ", "MODE ", "PASV", "PORT "}
	for _, cmd := range ftpCommands {
		if strings.HasPrefix(dataStr, cmd) {
			return true
		}
	}
	
	return false
}

func (ftp *FTPAnalyzer) getOrCreateSession(sessionKey string, flow gopacket.Flow) *FTPSession {
	if session, exists := ftp.sessions[sessionKey]; exists {
		session.LastActivity = time.Now()
		return session
	}
	
	session := &FTPSession{
		ID:           fmt.Sprintf("ftp_%d", time.Now().UnixNano()),
		ClientIP:     net.ParseIP(flow.Src().String()),
		ServerIP:     net.ParseIP(flow.Dst().String()),
		ControlPort:  uint16(flow.Dst().FastHash()),
		Commands:     make([]FTPCommand, 0),
		Transfers:    make([]FileTransfer, 0),
		StartTime:    time.Now(),
		LastActivity: time.Now(),
		TransferType: "ASCII",
		TransferMode: "Stream",
	}
	
	ftp.sessions[sessionKey] = session
	return session
}

func (ftp *FTPAnalyzer) analyzeControlChannel(session *FTPSession, reader *bufio.Reader) []ProtocolEvent {
	var events []ProtocolEvent
	
	for {
		line, err := ReadLine(reader)
		if err != nil {
			break
		}
		
		if line == "" {
			continue
		}
		
		// Determine if this is a command or response
		if ftp.isCommand(line) {
			event := ftp.processCommand(session, line)
			if event != nil {
				events = append(events, *event)
			}
		} else if ftp.isResponse(line) {
			event := ftp.processResponse(session, line)
			if event != nil {
				events = append(events, *event)
			}
		}
	}
	
	return events
}

func (ftp *FTPAnalyzer) analyzeDataChannel(session *FTPSession, reader *bufio.Reader) []ProtocolEvent {
	var events []ProtocolEvent
	
	// Read all data from the data channel
	data := make([]byte, 0)
	buf := make([]byte, 4096)
	
	for {
		n, err := reader.Read(buf)
		if err != nil {
			break
		}
		data = append(data, buf[:n]...)
	}
	
	// Create data transfer event
	event := ProtocolEvent{
		ID:        GenerateEventID("FTP"),
		Protocol:  "FTP",
		EventType: EventTypeDataTransfer,
		Data: map[string]interface{}{
			"session_id": session.ID,
			"data_size":  len(data),
			"data_type":  session.TransferType,
		},
		Raw: data,
	}
	
	events = append(events, event)
	
	return events
}

func (ftp *FTPAnalyzer) isCommand(line string) bool {
	// Commands are typically 3-4 characters followed by space or end of line
	if len(line) < 3 {
		return false
	}
	
	command := strings.Fields(line)[0]
	return len(command) >= 3 && len(command) <= 4 && strings.ToUpper(command) == command
}

func (ftp *FTPAnalyzer) isResponse(line string) bool {
	// Responses start with a 3-digit number
	if len(line) < 3 {
		return false
	}
	
	code := line[:3]
	_, err := strconv.Atoi(code)
	return err == nil
}

func (ftp *FTPAnalyzer) processCommand(session *FTPSession, line string) *ProtocolEvent {
	parts := strings.SplitN(line, " ", 2)
	command := strings.ToUpper(parts[0])
	var arguments string
	if len(parts) > 1 {
		arguments = parts[1]
	}
	
	// Add to session commands
	ftpCmd := FTPCommand{
		Command:   command,
		Arguments: arguments,
		Timestamp: time.Now(),
	}
	session.Commands = append(session.Commands, ftpCmd)
	
	// Create event based on command type
	event := &ProtocolEvent{
		ID:        GenerateEventID("FTP"),
		Protocol:  "FTP",
		EventType: EventTypeCommand,
		Command:   line,
		Data: map[string]interface{}{
			"session_id": session.ID,
			"command":    command,
			"arguments":  arguments,
		},
	}
	
	// Handle specific commands
	switch command {
	case "USER":
		session.Username = arguments
		event.Username = arguments
		event.EventType = EventTypeAuthentication
		
	case "PASS":
		event.EventType = EventTypeAuthentication
		event.Data["password_provided"] = true
		
	case "STOR":
		// File upload
		transfer := FileTransfer{
			Filename:  arguments,
			Direction: DirectionUpload,
			StartTime: time.Now(),
			Mode:      session.TransferMode,
			Type:      session.TransferType,
		}
		session.Transfers = append(session.Transfers, transfer)
		
		event.EventType = EventTypeFileTransfer
		event.Filename = arguments
		event.Direction = DirectionUpload
		
	case "RETR":
		// File download
		transfer := FileTransfer{
			Filename:  arguments,
			Direction: DirectionDownload,
			StartTime: time.Now(),
			Mode:      session.TransferMode,
			Type:      session.TransferType,
		}
		session.Transfers = append(session.Transfers, transfer)
		
		event.EventType = EventTypeFileTransfer
		event.Filename = arguments
		event.Direction = DirectionDownload
		
	case "CWD":
		session.CurrentDir = arguments
		event.Data["directory"] = arguments
		
	case "TYPE":
		session.TransferType = arguments
		event.Data["transfer_type"] = arguments
		
	case "MODE":
		session.TransferMode = arguments
		event.Data["transfer_mode"] = arguments
		
	case "PASV":
		session.PassiveMode = true
		event.Data["passive_mode"] = true
		
	case "PORT":
		session.PassiveMode = false
		dataAddr := ftp.parsePortCommand(arguments)
		if dataAddr != nil {
			session.DataConnection = dataAddr
			event.Data["data_connection"] = dataAddr.String()
		}
		
	case "QUIT":
		event.EventType = EventTypeDisconnection
	}
	
	return event
}

func (ftp *FTPAnalyzer) processResponse(session *FTPSession, line string) *ProtocolEvent {
	// Parse response code
	code, err := strconv.Atoi(line[:3])
	if err != nil {
		return nil
	}
	
	message := ""
	if len(line) > 4 {
		message = line[4:]
	}
	
	// Update last command with response
	if len(session.Commands) > 0 {
		lastCmd := &session.Commands[len(session.Commands)-1]
		lastCmd.Response = line
		lastCmd.Code = code
	}
	
	event := &ProtocolEvent{
		ID:        GenerateEventID("FTP"),
		Protocol:  "FTP",
		EventType: EventTypeCommand,
		Response:  line,
		Status:    fmt.Sprintf("%d", code),
		Data: map[string]interface{}{
			"session_id":     session.ID,
			"response_code":  code,
			"response_text":  message,
		},
	}
	
	// Handle specific response codes
	switch {
	case code == 220:
		// Welcome message
		event.EventType = EventTypeConnection
		event.Data["server_banner"] = message
		
	case code == 230:
		// User logged in
		session.Authenticated = true
		event.EventType = EventTypeAuthentication
		event.Username = session.Username
		event.Data["login_successful"] = true
		
	case code == 530:
		// Login failed
		event.EventType = EventTypeAuthentication
		event.Username = session.Username
		event.Data["login_failed"] = true
		
	case code >= 200 && code < 300:
		// Success responses
		event.Data["success"] = true
		
	case code >= 400:
		// Error responses
		event.EventType = EventTypeError
		event.Data["error"] = true
		
	case code == 227:
		// Entering passive mode
		dataAddr := ftp.parsePassiveResponse(message)
		if dataAddr != nil {
			session.DataConnection = dataAddr
			event.Data["data_connection"] = dataAddr.String()
		}
		
	case code == 150:
		// File transfer starting
		event.EventType = EventTypeFileTransfer
		if strings.Contains(message, "bytes") {
			size := ftp.extractFileSize(message)
			if size > 0 {
				event.FileSize = size
				// Update transfer in session
				if len(session.Transfers) > 0 {
					session.Transfers[len(session.Transfers)-1].Size = size
				}
			}
		}
		
	case code == 226:
		// Transfer complete
		event.EventType = EventTypeFileTransfer
		event.Data["transfer_complete"] = true
		// Mark last transfer as complete
		if len(session.Transfers) > 0 {
			transfer := &session.Transfers[len(session.Transfers)-1]
			transfer.Complete = true
			transfer.EndTime = time.Now()
		}
	}
	
	return event
}

func (ftp *FTPAnalyzer) parsePortCommand(portStr string) *net.TCPAddr {
	// PORT command format: h1,h2,h3,h4,p1,p2
	parts := strings.Split(portStr, ",")
	if len(parts) != 6 {
		return nil
	}
	
	var nums [6]int
	for i, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil {
			return nil
		}
		// Validate IP octets (0-255) and port parts (0-255)
		if num < 0 || num > 255 {
			return nil
		}
		nums[i] = num
	}
	
	ip := net.IPv4(byte(nums[0]), byte(nums[1]), byte(nums[2]), byte(nums[3]))
	port := nums[4]*256 + nums[5]
	
	return &net.TCPAddr{
		IP:   ip,
		Port: port,
	}
}

func (ftp *FTPAnalyzer) parsePassiveResponse(response string) *net.TCPAddr {
	// Extract IP and port from passive response: "Entering Passive Mode (h1,h2,h3,h4,p1,p2)"
	re := regexp.MustCompile(`\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)`)
	matches := re.FindStringSubmatch(response)
	
	if len(matches) != 7 {
		return nil
	}
	
	var nums [6]int
	for i := 1; i < 7; i++ {
		num, err := strconv.Atoi(matches[i])
		if err != nil {
			return nil
		}
		// Validate IP octets (0-255) and port parts (0-255)
		if num < 0 || num > 255 {
			return nil
		}
		nums[i-1] = num
	}
	
	ip := net.IPv4(byte(nums[0]), byte(nums[1]), byte(nums[2]), byte(nums[3]))
	port := nums[4]*256 + nums[5]
	
	return &net.TCPAddr{
		IP:   ip,
		Port: port,
	}
}

func (ftp *FTPAnalyzer) extractFileSize(message string) int64 {
	// Extract file size from messages like "Opening data connection for file.txt (1234 bytes)"
	re := regexp.MustCompile(`\((\d+)\s+bytes?\)`)
	matches := re.FindStringSubmatch(message)
	
	if len(matches) > 1 {
		size, err := strconv.ParseInt(matches[1], 10, 64)
		if err == nil {
			return size
		}
	}
	
	return 0
}

// GetActiveSessions returns all active FTP sessions
func (ftp *FTPAnalyzer) GetActiveSessions() []*FTPSession {
	var sessions []*FTPSession
	cutoff := time.Now().Add(-30 * time.Minute) // Consider sessions older than 30 minutes as inactive
	
	for key, session := range ftp.sessions {
		if session.LastActivity.After(cutoff) {
			sessions = append(sessions, session)
		} else {
			// Clean up old sessions
			delete(ftp.sessions, key)
		}
	}
	
	return sessions
}

// GetSessionStats returns FTP session statistics
func (ftp *FTPAnalyzer) GetSessionStats() map[string]interface{} {
	activeSessions := ftp.GetActiveSessions()
	
	stats := map[string]interface{}{
		"active_sessions":     len(activeSessions),
		"authenticated_sessions": 0,
		"total_transfers":     0,
		"uploads":            0,
		"downloads":          0,
		"total_bytes":        int64(0),
	}
	
	for _, session := range activeSessions {
		if session.Authenticated {
			stats["authenticated_sessions"] = stats["authenticated_sessions"].(int) + 1
		}
		
		stats["total_transfers"] = stats["total_transfers"].(int) + len(session.Transfers)
		
		for _, transfer := range session.Transfers {
			if transfer.Direction == DirectionUpload {
				stats["uploads"] = stats["uploads"].(int) + 1
			} else {
				stats["downloads"] = stats["downloads"].(int) + 1
			}
			stats["total_bytes"] = stats["total_bytes"].(int64) + transfer.Size
		}
	}
	
	return stats
}