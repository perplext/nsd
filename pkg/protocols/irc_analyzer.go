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

// IRCAnalyzer analyzes IRC protocol traffic including DCC file transfers
type IRCAnalyzer struct {
	BaseAnalyzer
	sessions    map[string]*IRCSession
	dccSessions map[string]*DCCSession
}

// IRCSession represents an active IRC session
type IRCSession struct {
	ID           string
	ClientIP     net.IP
	ServerIP     net.IP
	Port         uint16
	Nickname     string
	Username     string
	Realname     string
	ServerName   string
	Channels     []string
	Messages     []IRCMessage
	Commands     []IRCCommand
	DCCOffers    []DCCOffer
	StartTime    time.Time
	LastActivity time.Time
	Registered   bool
	Away         bool
}

// DCCSession represents a DCC file transfer session
type DCCSession struct {
	ID           string
	Type         DCCType
	ClientIP     net.IP
	ServerIP     net.IP
	Port         uint16
	Filename     string
	FileSize     int64
	Sender       string
	Receiver     string
	BytesTransferred int64
	StartTime    time.Time
	EndTime      time.Time
	Complete     bool
	Active       bool
}

// DCCType represents the type of DCC session
type DCCType string

const (
	DCCTypeSend DCCType = "SEND"
	DCCTypeChat DCCType = "CHAT"
	DCCTypeGet  DCCType = "GET"
)

// IRCMessage represents an IRC message
type IRCMessage struct {
	Prefix    string
	Command   string
	Params    []string
	Trailing  string
	Timestamp time.Time
	Channel   string
	Sender    string
	Message   string
	Type      MessageType
}

// MessageType categorizes IRC messages
type MessageType string

const (
	MessageTypePrivmsg MessageType = "PRIVMSG"
	MessageTypeNotice  MessageType = "NOTICE"
	MessageTypeJoin    MessageType = "JOIN"
	MessageTypePart    MessageType = "PART"
	MessageTypeQuit    MessageType = "QUIT"
	MessageTypeKick    MessageType = "KICK"
	MessageTypeMode    MessageType = "MODE"
	MessageTypeTopic   MessageType = "TOPIC"
	MessageTypeDCC     MessageType = "DCC"
)

// IRCCommand represents an IRC command
type IRCCommand struct {
	Command   string
	Params    []string
	Response  string
	Timestamp time.Time
}

// DCCOffer represents a DCC file transfer offer
type DCCOffer struct {
	ID       string
	Type     DCCType
	Filename string
	IP       net.IP
	Port     uint16
	Size     int64
	Sender   string
	Target   string
	Timestamp time.Time
}

// NewIRCAnalyzer creates a new IRC analyzer
func NewIRCAnalyzer() ProtocolAnalyzer {
	return &IRCAnalyzer{
		BaseAnalyzer: BaseAnalyzer{
			protocolName: "IRC",
			ports:        []uint16{6667, 6668, 6669, 6697, 7000}, // Standard IRC ports
		},
		sessions:    make(map[string]*IRCSession),
		dccSessions: make(map[string]*DCCSession),
	}
}

// AnalyzeStream analyzes an IRC stream
func (irc *IRCAnalyzer) AnalyzeStream(flow gopacket.Flow, reader *tcpreader.ReaderStream) []ProtocolEvent {
	var events []ProtocolEvent
	buf := bufio.NewReader(reader)
	
	// Create session key
	sessionKey := fmt.Sprintf("%s->%s", flow.Src().String(), flow.Dst().String())
	
	// Check if this might be a DCC session
	srcPort := uint16(flow.Src().FastHash())
	dstPort := uint16(flow.Dst().FastHash())
	
	if irc.isDCCPort(srcPort) || irc.isDCCPort(dstPort) {
		// Handle DCC session
		events = append(events, irc.analyzeDCCStream(sessionKey, flow, buf)...)
	} else {
		// Handle regular IRC session
		session := irc.getOrCreateSession(sessionKey, flow)
		events = append(events, irc.analyzeIRCStream(session, buf)...)
	}
	
	return events
}

// IsProtocolTraffic determines if data is IRC traffic
func (irc *IRCAnalyzer) IsProtocolTraffic(data []byte) bool {
	dataStr := string(data)
	
	// Check for IRC server responses
	if strings.HasPrefix(dataStr, ":") && strings.Contains(dataStr, " ") {
		parts := strings.Fields(dataStr)
		if len(parts) >= 2 {
			// Check for numeric IRC responses (001-999)
			if code, err := strconv.Atoi(parts[1]); err == nil && code >= 1 && code <= 999 {
				return true
			}
		}
	}
	
	// Check for common IRC commands
	ircCommands := []string{"NICK ", "USER ", "JOIN ", "PART ", "PRIVMSG ", "NOTICE ", "QUIT", "PING ", "PONG ", "MODE ", "TOPIC ", "KICK ", "WHO ", "WHOIS "}
	dataUpper := strings.ToUpper(dataStr)
	
	for _, cmd := range ircCommands {
		if strings.HasPrefix(dataUpper, cmd) {
			return true
		}
	}
	
	// Check for DCC offers
	if strings.Contains(dataUpper, "DCC SEND") || strings.Contains(dataUpper, "DCC CHAT") {
		return true
	}
	
	return false
}

func (irc *IRCAnalyzer) getOrCreateSession(sessionKey string, flow gopacket.Flow) *IRCSession {
	if session, exists := irc.sessions[sessionKey]; exists {
		session.LastActivity = time.Now()
		return session
	}
	
	session := &IRCSession{
		ID:           fmt.Sprintf("irc_%d", time.Now().UnixNano()),
		ClientIP:     net.ParseIP(flow.Src().String()),
		ServerIP:     net.ParseIP(flow.Dst().String()),
		Port:         uint16(flow.Dst().FastHash()),
		Channels:     make([]string, 0),
		Messages:     make([]IRCMessage, 0),
		Commands:     make([]IRCCommand, 0),
		DCCOffers:    make([]DCCOffer, 0),
		StartTime:    time.Now(),
		LastActivity: time.Now(),
	}
	
	irc.sessions[sessionKey] = session
	return session
}

func (irc *IRCAnalyzer) analyzeIRCStream(session *IRCSession, reader *bufio.Reader) []ProtocolEvent {
	var events []ProtocolEvent
	
	for {
		line, err := ReadLine(reader)
		if err != nil {
			break
		}
		
		if line == "" {
			continue
		}
		
		// Parse IRC message
		message := irc.parseIRCMessage(line)
		if message != nil {
			session.Messages = append(session.Messages, *message)
			
			event := irc.processIRCMessage(session, message)
			if event != nil {
				events = append(events, *event)
			}
		}
	}
	
	return events
}

func (irc *IRCAnalyzer) analyzeDCCStream(sessionKey string, flow gopacket.Flow, reader *bufio.Reader) []ProtocolEvent {
	var events []ProtocolEvent
	
	// Create or find DCC session
	dccSession := irc.getOrCreateDCCSession(sessionKey, flow)
	
	// Count bytes transferred
	data := make([]byte, 4096)
	totalBytes := 0
	
	for {
		n, err := reader.Read(data)
		if err != nil {
			break
		}
		totalBytes += n
		dccSession.BytesTransferred += int64(n)
	}
	
	if totalBytes > 0 {
		event := ProtocolEvent{
			ID:        GenerateEventID("IRC"),
			Protocol:  "IRC",
			EventType: EventTypeFileTransfer,
			Data: map[string]interface{}{
				"dcc_session_id":   dccSession.ID,
				"dcc_type":         string(dccSession.Type),
				"filename":         dccSession.Filename,
				"bytes_transferred": totalBytes,
				"total_bytes":      dccSession.BytesTransferred,
				"sender":           dccSession.Sender,
				"receiver":         dccSession.Receiver,
			},
		}
		
		if dccSession.Filename != "" {
			event.Filename = dccSession.Filename
		}
		
		events = append(events, event)
		
		// Check if transfer is complete
		if dccSession.FileSize > 0 && dccSession.BytesTransferred >= dccSession.FileSize {
			dccSession.Complete = true
			dccSession.EndTime = time.Now()
		}
	}
	
	return events
}

func (irc *IRCAnalyzer) parseIRCMessage(line string) *IRCMessage {
	message := &IRCMessage{
		Timestamp: time.Now(),
	}
	
	// IRC message format: [':' prefix SPACE] command [params] [':' trailing]
	remaining := line
	
	// Extract prefix if present
	if strings.HasPrefix(remaining, ":") {
		parts := strings.SplitN(remaining[1:], " ", 2)
		if len(parts) == 2 {
			message.Prefix = parts[0]
			remaining = parts[1]
		}
	}
	
	// Extract command and parameters
	parts := strings.Split(remaining, " :")
	cmdParts := strings.Fields(parts[0])
	
	if len(cmdParts) > 0 {
		message.Command = strings.ToUpper(cmdParts[0])
		if len(cmdParts) > 1 {
			message.Params = cmdParts[1:]
		}
	}
	
	// Extract trailing parameter
	if len(parts) > 1 {
		message.Trailing = strings.Join(parts[1:], " :")
	}
	
	// Set message type
	message.Type = MessageType(message.Command)
	
	// Extract sender from prefix
	if message.Prefix != "" {
		if strings.Contains(message.Prefix, "!") {
			message.Sender = strings.Split(message.Prefix, "!")[0]
		}
	}
	
	// For PRIVMSG and NOTICE, extract channel and message
	if message.Command == "PRIVMSG" || message.Command == "NOTICE" {
		if len(message.Params) > 0 {
			message.Channel = message.Params[0]
			message.Message = message.Trailing
		}
	}
	
	return message
}

func (irc *IRCAnalyzer) processIRCMessage(session *IRCSession, message *IRCMessage) *ProtocolEvent {
	event := &ProtocolEvent{
		ID:        GenerateEventID("IRC"),
		Protocol:  "IRC",
		EventType: EventTypeCommand,
		Command:   message.Command,
		Data: map[string]interface{}{
			"session_id": session.ID,
			"command":    message.Command,
			"sender":     message.Sender,
		},
	}
	
	switch message.Command {
	case "NICK":
		if len(message.Params) > 0 {
			session.Nickname = message.Params[0]
			event.Data["nickname"] = message.Params[0]
		}
		
	case "USER":
		if len(message.Params) >= 4 {
			session.Username = message.Params[0]
			session.Realname = message.Trailing
			event.Data["username"] = session.Username
			event.Data["realname"] = session.Realname
		}
		
	case "JOIN":
		channel := message.Trailing
		if channel == "" && len(message.Params) > 0 {
			channel = message.Params[0]
		}
		if channel != "" {
			session.Channels = append(session.Channels, channel)
			event.Data["channel"] = channel
		}
		
	case "PART":
		if len(message.Params) > 0 {
			channel := message.Params[0]
			// Remove channel from session
			for i, ch := range session.Channels {
				if ch == channel {
					session.Channels = append(session.Channels[:i], session.Channels[i+1:]...)
					break
				}
			}
			event.Data["channel"] = channel
		}
		
	case "PRIVMSG":
		event.Data["channel"] = message.Channel
		event.Data["message"] = message.Message
		
		// Check for DCC offers
		if strings.Contains(strings.ToUpper(message.Message), "DCC") {
			dccOffer := irc.parseDCCOffer(message)
			if dccOffer != nil {
				session.DCCOffers = append(session.DCCOffers, *dccOffer)
				event.EventType = EventTypeFileTransfer
				event.Data["dcc_offer"] = map[string]interface{}{
					"type":     string(dccOffer.Type),
					"filename": dccOffer.Filename,
					"size":     dccOffer.Size,
					"ip":       dccOffer.IP.String(),
					"port":     dccOffer.Port,
				}
				event.Filename = dccOffer.Filename
				event.FileSize = dccOffer.Size
			}
		}
		
	case "QUIT":
		event.EventType = EventTypeDisconnection
		event.Data["quit_message"] = message.Trailing
		
	case "001": // RPL_WELCOME
		session.Registered = true
		session.ServerName = irc.extractServerName(message.Prefix)
		event.EventType = EventTypeConnection
		event.Data["registered"] = true
		event.Data["server_name"] = session.ServerName
		
	case "PING":
		event.Data["ping_data"] = message.Trailing
		
	case "PONG":
		event.Data["pong_data"] = message.Trailing
	}
	
	return event
}

func (irc *IRCAnalyzer) parseDCCOffer(message *IRCMessage) *DCCOffer {
	// DCC SEND filename ip port [size]
	// DCC CHAT chat ip port
	dccText := strings.ToUpper(message.Message)
	
	if !strings.Contains(dccText, "DCC") {
		return nil
	}
	
	re := regexp.MustCompile(`DCC\s+(SEND|CHAT)\s+(\S+)\s+(\d+)\s+(\d+)(?:\s+(\d+))?`)
	matches := re.FindStringSubmatch(dccText)
	
	if len(matches) < 5 {
		return nil
	}
	
	dccType := DCCType(matches[1])
	filename := matches[2]
	
	// Convert IP from decimal to dotted decimal
	ipNum, err := strconv.ParseUint(matches[3], 10, 32)
	if err != nil {
		return nil
	}
	ip := make(net.IP, 4)
	ip[0] = byte(ipNum >> 24)
	ip[1] = byte(ipNum >> 16)
	ip[2] = byte(ipNum >> 8)
	ip[3] = byte(ipNum)
	
	port, err := strconv.ParseUint(matches[4], 10, 16)
	if err != nil {
		return nil
	}
	
	var size int64
	if len(matches) > 5 && matches[5] != "" {
		size, _ = strconv.ParseInt(matches[5], 10, 64)
	}
	
	offer := &DCCOffer{
		ID:        fmt.Sprintf("dcc_%d", time.Now().UnixNano()),
		Type:      dccType,
		Filename:  filename,
		IP:        ip,
		Port:      uint16(port),
		Size:      size,
		Sender:    message.Sender,
		Timestamp: time.Now(),
	}
	
	// Extract target from channel or direct message
	if message.Channel != "" && !strings.HasPrefix(message.Channel, "#") {
		offer.Target = message.Channel
	}
	
	return offer
}

func (irc *IRCAnalyzer) getOrCreateDCCSession(sessionKey string, flow gopacket.Flow) *DCCSession {
	if session, exists := irc.dccSessions[sessionKey]; exists {
		return session
	}
	
	session := &DCCSession{
		ID:        fmt.Sprintf("dcc_%d", time.Now().UnixNano()),
		Type:      DCCTypeSend, // Default assumption
		ClientIP:  net.ParseIP(flow.Src().String()),
		ServerIP:  net.ParseIP(flow.Dst().String()),
		Port:      uint16(flow.Dst().FastHash()),
		StartTime: time.Now(),
		Active:    true,
	}
	
	// Try to match with existing DCC offers
	for _, ircSession := range irc.sessions {
		for _, offer := range ircSession.DCCOffers {
			if offer.Port == session.Port {
				session.Type = offer.Type
				session.Filename = offer.Filename
				session.FileSize = offer.Size
				session.Sender = offer.Sender
				session.Receiver = offer.Target
				break
			}
		}
	}
	
	irc.dccSessions[sessionKey] = session
	return session
}

func (irc *IRCAnalyzer) isDCCPort(port uint16) bool {
	// DCC typically uses high ports (1024-65535)
	// This is a heuristic - in practice we'd match against known DCC offers
	return port >= 1024
}

func (irc *IRCAnalyzer) extractServerName(prefix string) string {
	if prefix == "" {
		return ""
	}
	
	// Server names typically don't contain ! or @
	if !strings.Contains(prefix, "!") && !strings.Contains(prefix, "@") {
		return prefix
	}
	
	return ""
}

// GetActiveSessions returns all active IRC sessions
func (irc *IRCAnalyzer) GetActiveSessions() []*IRCSession {
	var sessions []*IRCSession
	cutoff := time.Now().Add(-30 * time.Minute)
	
	for key, session := range irc.sessions {
		if session.LastActivity.After(cutoff) {
			sessions = append(sessions, session)
		} else {
			delete(irc.sessions, key)
		}
	}
	
	return sessions
}

// GetActiveDCCSessions returns all active DCC sessions
func (irc *IRCAnalyzer) GetActiveDCCSessions() []*DCCSession {
	var sessions []*DCCSession
	cutoff := time.Now().Add(-2 * time.Hour) // DCC transfers can be longer
	
	for key, session := range irc.dccSessions {
		if session.StartTime.After(cutoff) && session.Active {
			sessions = append(sessions, session)
		} else if session.Complete || session.StartTime.Before(cutoff) {
			delete(irc.dccSessions, key)
		}
	}
	
	return sessions
}

// GetSessionStats returns IRC session statistics
func (irc *IRCAnalyzer) GetSessionStats() map[string]interface{} {
	activeSessions := irc.GetActiveSessions()
	activeDCCSessions := irc.GetActiveDCCSessions()
	
	stats := map[string]interface{}{
		"active_sessions":         len(activeSessions),
		"registered_sessions":     0,
		"active_dcc_sessions":     len(activeDCCSessions),
		"total_channels":         0,
		"total_dcc_offers":       0,
		"completed_dcc_transfers": 0,
		"total_dcc_bytes":        int64(0),
	}
	
	for _, session := range activeSessions {
		if session.Registered {
			stats["registered_sessions"] = stats["registered_sessions"].(int) + 1
		}
		stats["total_channels"] = stats["total_channels"].(int) + len(session.Channels)
		stats["total_dcc_offers"] = stats["total_dcc_offers"].(int) + len(session.DCCOffers)
	}
	
	for _, dccSession := range activeDCCSessions {
		if dccSession.Complete {
			stats["completed_dcc_transfers"] = stats["completed_dcc_transfers"].(int) + 1
		}
		stats["total_dcc_bytes"] = stats["total_dcc_bytes"].(int64) + dccSession.BytesTransferred
	}
	
	return stats
}

// GetDCCTransfers returns all DCC file transfers
func (irc *IRCAnalyzer) GetDCCTransfers() []DCCSession {
	var transfers []DCCSession
	
	for _, session := range irc.dccSessions {
		if session.Type == DCCTypeSend && session.Filename != "" {
			transfers = append(transfers, *session)
		}
	}
	
	return transfers
}