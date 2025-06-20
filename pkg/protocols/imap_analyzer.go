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

// IMAPAnalyzer analyzes IMAP protocol traffic
type IMAPAnalyzer struct {
	BaseAnalyzer
	sessions map[string]*IMAPSession
}

// IMAPSession represents an active IMAP session
type IMAPSession struct {
	ID               string
	ClientIP         net.IP
	ServerIP         net.IP
	Port             uint16
	Username         string
	AuthMethod       string
	State            IMAPState
	Commands         []IMAPCommand
	Capabilities     []string
	Mailboxes        []IMAPMailbox
	SelectedMailbox  *IMAPMailbox
	Messages         []IMAPMessage
	StartTime        time.Time
	LastActivity     time.Time
	Authenticated    bool
	TLSEnabled       bool
	CurrentTag       string
}

// IMAPState represents the state of an IMAP connection
type IMAPState int

const (
	IMAPStateNotAuthenticated IMAPState = iota
	IMAPStateAuthenticated
	IMAPStateSelected
	IMAPStateLogout
)

// IMAPCommand represents an IMAP command
type IMAPCommand struct {
	Tag       string
	Command   string
	Arguments []string
	Response  []string
	Status    string
	Timestamp time.Time
}

// IMAPMailbox represents an IMAP mailbox
type IMAPMailbox struct {
	Name         string
	Attributes   []string
	Delimiter    string
	MessageCount int
	RecentCount  int
	UnseenCount  int
	UIDValidity  int64
	UIDNext      int64
	Flags        []string
}

// IMAPMessage represents an IMAP message
type IMAPMessage struct {
	UID          int64
	SequenceNum  int
	Mailbox      string
	Subject      string
	From         string
	To           []string
	Date         time.Time
	Size         int64
	Flags        []string
	Headers      map[string]string
	Body         string
	Attachments  []EmailAttachment
	Fetched      bool
	Timestamp    time.Time
}

// NewIMAPAnalyzer creates a new IMAP analyzer
func NewIMAPAnalyzer() ProtocolAnalyzer {
	return &IMAPAnalyzer{
		BaseAnalyzer: BaseAnalyzer{
			protocolName: "IMAP",
			ports:        []uint16{143, 993}, // IMAP and IMAPS
		},
		sessions: make(map[string]*IMAPSession),
	}
}

// AnalyzeStream analyzes an IMAP stream
func (imap *IMAPAnalyzer) AnalyzeStream(flow gopacket.Flow, reader *tcpreader.ReaderStream) []ProtocolEvent {
	var events []ProtocolEvent
	buf := bufio.NewReader(reader)
	
	// Create session key
	sessionKey := fmt.Sprintf("%s->%s", flow.Src().String(), flow.Dst().String())
	
	// Get or create session
	session := imap.getOrCreateSession(sessionKey, flow)
	
	// Analyze IMAP protocol
	events = append(events, imap.analyzeIMAPStream(session, buf)...)
	
	return events
}

// IsProtocolTraffic determines if data is IMAP traffic
func (imap *IMAPAnalyzer) IsProtocolTraffic(data []byte) bool {
	dataStr := strings.ToUpper(string(data))
	
	// Check for IMAP server greeting
	if strings.Contains(dataStr, "* OK") && (strings.Contains(dataStr, "IMAP") || strings.Contains(dataStr, "READY")) {
		return true
	}
	
	// Check for common IMAP commands (tagged)
	imapCommands := []string{"LOGIN", "SELECT", "EXAMINE", "FETCH", "STORE", "SEARCH", "LIST", "LSUB", "STATUS", "APPEND", "CHECK", "CLOSE", "EXPUNGE", "COPY", "UID", "LOGOUT", "NOOP", "CAPABILITY", "STARTTLS", "AUTHENTICATE"}
	
	// Look for tagged commands (e.g., "A001 LOGIN user pass")
	lines := strings.Split(dataStr, "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			for _, cmd := range imapCommands {
				if parts[1] == cmd {
					return true
				}
			}
		}
	}
	
	// Check for IMAP responses
	if strings.HasPrefix(dataStr, "* ") || strings.Contains(dataStr, " OK ") || strings.Contains(dataStr, " NO ") || strings.Contains(dataStr, " BAD ") {
		return true
	}
	
	return false
}

func (imap *IMAPAnalyzer) getOrCreateSession(sessionKey string, flow gopacket.Flow) *IMAPSession {
	if session, exists := imap.sessions[sessionKey]; exists {
		session.LastActivity = time.Now()
		return session
	}
	
	session := &IMAPSession{
		ID:           fmt.Sprintf("imap_%d", time.Now().UnixNano()),
		ClientIP:     net.ParseIP(flow.Src().String()),
		ServerIP:     net.ParseIP(flow.Dst().String()),
		Port:         uint16(flow.Dst().FastHash() % 65536),
		State:        IMAPStateNotAuthenticated,
		Commands:     make([]IMAPCommand, 0),
		Capabilities: make([]string, 0),
		Mailboxes:    make([]IMAPMailbox, 0),
		Messages:     make([]IMAPMessage, 0),
		StartTime:    time.Now(),
		LastActivity: time.Now(),
	}
	
	imap.sessions[sessionKey] = session
	return session
}

func (imap *IMAPAnalyzer) analyzeIMAPStream(session *IMAPSession, reader *bufio.Reader) []ProtocolEvent {
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
		if imap.isCommand(line) {
			event := imap.processCommand(session, line)
			if event != nil {
				events = append(events, *event)
			}
		} else if imap.isResponse(line) {
			event := imap.processResponse(session, line)
			if event != nil {
				events = append(events, *event)
			}
		}
	}
	
	return events
}

func (imap *IMAPAnalyzer) isCommand(line string) bool {
	// IMAP commands start with a tag followed by command
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return false
	}
	
	// Tag is typically alphanumeric
	tag := parts[0]
	command := strings.ToUpper(parts[1])
	
	if len(tag) == 0 || strings.HasPrefix(tag, "*") {
		return false
	}
	
	imapCommands := []string{"LOGIN", "SELECT", "EXAMINE", "FETCH", "STORE", "SEARCH", "LIST", "LSUB", "STATUS", "APPEND", "CHECK", "CLOSE", "EXPUNGE", "COPY", "UID", "LOGOUT", "NOOP", "CAPABILITY", "STARTTLS", "AUTHENTICATE", "RENAME", "DELETE", "CREATE", "SUBSCRIBE", "UNSUBSCRIBE"}
	
	for _, cmd := range imapCommands {
		if command == cmd {
			return true
		}
	}
	
	return false
}

func (imap *IMAPAnalyzer) isResponse(line string) bool {
	// IMAP responses start with * (untagged) or tag followed by status
	if strings.HasPrefix(line, "* ") {
		return true
	}
	
	parts := strings.Fields(line)
	if len(parts) >= 2 {
		status := strings.ToUpper(parts[1])
		return status == "OK" || status == "NO" || status == "BAD"
	}
	
	return false
}

func (imap *IMAPAnalyzer) processCommand(session *IMAPSession, line string) *ProtocolEvent {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}
	
	tag := parts[0]
	command := strings.ToUpper(parts[1])
	var arguments []string
	if len(parts) > 2 {
		arguments = parts[2:]
	}
	
	// Add to session commands
	imapCmd := IMAPCommand{
		Tag:       tag,
		Command:   command,
		Arguments: arguments,
		Response:  make([]string, 0),
		Timestamp: time.Now(),
	}
	session.Commands = append(session.Commands, imapCmd)
	session.CurrentTag = tag
	
	// Create event
	event := &ProtocolEvent{
		ID:        GenerateEventID("IMAP"),
		Protocol:  "IMAP",
		EventType: EventTypeCommand,
		Command:   line,
		Data: map[string]interface{}{
			"session_id": session.ID,
			"tag":        tag,
			"command":    command,
			"arguments":  arguments,
		},
	}
	
	// Handle specific commands
	switch command {
	case "LOGIN":
		if len(arguments) >= 2 {
			session.Username = arguments[0]
			event.Username = arguments[0]
			event.EventType = EventTypeAuthentication
			event.Data["auth_method"] = "LOGIN"
		}
		
	case "AUTHENTICATE":
		if len(arguments) > 0 {
			session.AuthMethod = arguments[0]
			event.EventType = EventTypeAuthentication
			event.Data["auth_method"] = arguments[0]
		}
		
	case "STARTTLS":
		event.Data["tls_requested"] = true
		
	case "CAPABILITY":
		event.Data["requesting_capabilities"] = true
		
	case "SELECT", "EXAMINE":
		if len(arguments) > 0 {
			mailboxName := arguments[0]
			event.Data["mailbox"] = mailboxName
			if command == "SELECT" {
				session.State = IMAPStateSelected
			}
		}
		
	case "LIST", "LSUB":
		event.Data["listing_mailboxes"] = true
		if len(arguments) >= 2 {
			event.Data["reference"] = arguments[0]
			event.Data["pattern"] = arguments[1]
		}
		
	case "FETCH":
		if len(arguments) >= 2 {
			event.EventType = EventTypeEmail
			event.Data["sequence_set"] = arguments[0]
			event.Data["fetch_items"] = strings.Join(arguments[1:], " ")
		}
		
	case "SEARCH":
		event.Data["search_criteria"] = strings.Join(arguments, " ")
		
	case "STORE":
		if len(arguments) >= 3 {
			event.Data["sequence_set"] = arguments[0]
			event.Data["store_operation"] = arguments[1]
			event.Data["flags"] = strings.Join(arguments[2:], " ")
		}
		
	case "COPY":
		if len(arguments) >= 2 {
			event.Data["sequence_set"] = arguments[0]
			event.Data["destination_mailbox"] = arguments[1]
		}
		
	case "APPEND":
		if len(arguments) >= 1 {
			event.EventType = EventTypeEmail
			event.Data["destination_mailbox"] = arguments[0]
		}
		
	case "LOGOUT":
		event.EventType = EventTypeDisconnection
		session.State = IMAPStateLogout
	}
	
	return event
}

func (imap *IMAPAnalyzer) processResponse(session *IMAPSession, line string) *ProtocolEvent {
	event := &ProtocolEvent{
		ID:        GenerateEventID("IMAP"),
		Protocol:  "IMAP",
		EventType: EventTypeCommand,
		Response:  line,
		Data: map[string]interface{}{
			"session_id": session.ID,
		},
	}
	
	// Update last command with response
	if len(session.Commands) > 0 {
		lastCmd := &session.Commands[len(session.Commands)-1]
		lastCmd.Response = append(lastCmd.Response, line)
	}
	
	if strings.HasPrefix(line, "* ") {
		// Untagged response
		event = imap.processUntaggedResponse(session, line, event)
	} else {
		// Tagged response
		event = imap.processTaggedResponse(session, line, event)
	}
	
	return event
}

func (imap *IMAPAnalyzer) processUntaggedResponse(session *IMAPSession, line string, event *ProtocolEvent) *ProtocolEvent {
	parts := strings.Fields(line[2:]) // Remove "* "
	if len(parts) == 0 {
		return event
	}
	
	responseType := strings.ToUpper(parts[0])
	
	switch responseType {
	case "OK":
		if strings.Contains(line, "CAPABILITY") {
			caps := imap.extractCapabilities(line)
			session.Capabilities = caps
			event.Data["capabilities"] = caps
		}
		
	case "CAPABILITY":
		if len(parts) > 1 {
			session.Capabilities = parts[1:]
			event.Data["capabilities"] = parts[1:]
		}
		
	case "LIST", "LSUB":
		mailbox := imap.parseMailboxResponse(parts)
		if mailbox != nil {
			session.Mailboxes = append(session.Mailboxes, *mailbox)
			event.Data["mailbox_info"] = map[string]interface{}{
				"name":       mailbox.Name,
				"attributes": mailbox.Attributes,
				"delimiter":  mailbox.Delimiter,
			}
		}
		
	case "STATUS":
		if len(parts) >= 3 {
			mailboxName := parts[1]
			statusItems := imap.parseStatusResponse(parts[2:])
			event.Data["mailbox"] = mailboxName
			event.Data["status"] = statusItems
		}
		
	default:
		// Check if it's a number (message count, EXISTS, RECENT, etc.)
		if num, err := strconv.Atoi(responseType); err == nil {
			if len(parts) > 1 {
				msgType := strings.ToUpper(parts[1])
				switch msgType {
				case "EXISTS":
					event.Data["message_count"] = num
					if session.SelectedMailbox != nil {
						session.SelectedMailbox.MessageCount = num
					}
					
				case "RECENT":
					event.Data["recent_count"] = num
					if session.SelectedMailbox != nil {
						session.SelectedMailbox.RecentCount = num
					}
					
				case "FETCH":
					event.EventType = EventTypeEmail
					fetchData := imap.parseFetchResponse(parts[2:])
					if fetchData != nil {
						event.Data["message_number"] = num
						event.Data["fetch_data"] = fetchData
						
						// Create or update message
						message := imap.createOrUpdateMessage(session, num, fetchData)
						if message != nil {
							event.Data["subject"] = message.Subject
							event.Data["from"] = message.From
							event.Data["size"] = message.Size
						}
					}
				}
			}
		}
	}
	
	return event
}

func (imap *IMAPAnalyzer) processTaggedResponse(session *IMAPSession, line string, event *ProtocolEvent) *ProtocolEvent {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return event
	}
	
	tag := parts[0]
	status := strings.ToUpper(parts[1])
	var message string
	if len(parts) > 2 {
		message = strings.Join(parts[2:], " ")
	}
	
	event.Data["tag"] = tag
	event.Data["status"] = status
	event.Data["message"] = message
	
	// Update command status
	if len(session.Commands) > 0 {
		lastCmd := &session.Commands[len(session.Commands)-1]
		if lastCmd.Tag == tag {
			lastCmd.Status = status
		}
	}
	
	// Handle specific command completions
	if len(session.Commands) > 0 {
		lastCmd := session.Commands[len(session.Commands)-1]
		if lastCmd.Tag == tag {
			switch lastCmd.Command {
			case "LOGIN":
				if status == "OK" {
					session.Authenticated = true
					session.State = IMAPStateAuthenticated
					event.EventType = EventTypeAuthentication
					event.Username = session.Username
					event.Data["login_successful"] = true
				} else {
					event.EventType = EventTypeAuthentication
					event.Username = session.Username
					event.Data["login_failed"] = true
				}
				
			case "SELECT", "EXAMINE":
				if status == "OK" {
					// Extract mailbox info from previous untagged responses
					if len(lastCmd.Arguments) > 0 {
						mailboxName := lastCmd.Arguments[0]
						mailbox := imap.findOrCreateMailbox(session, mailboxName)
						session.SelectedMailbox = mailbox
						event.Data["selected_mailbox"] = mailboxName
					}
				}
				
			case "STARTTLS":
				if status == "OK" {
					session.TLSEnabled = true
					event.Data["tls_enabled"] = true
				}
			}
		}
	}
	
	return event
}

func (imap *IMAPAnalyzer) extractCapabilities(line string) []string {
	// Extract capabilities from responses like "* OK [CAPABILITY IMAP4rev1 ...]"
	re := regexp.MustCompile(`\[CAPABILITY\s+([^\]]+)\]`)
	matches := re.FindStringSubmatch(line)
	
	if len(matches) > 1 {
		return strings.Fields(matches[1])
	}
	
	return []string{}
}

func (imap *IMAPAnalyzer) parseMailboxResponse(parts []string) *IMAPMailbox {
	// LIST/LSUB response format: (attributes) "delimiter" "name"
	if len(parts) < 3 {
		return nil
	}
	
	// Extract attributes (simplified)
	var attributes []string
	if strings.HasPrefix(parts[0], "(") {
		attrStr := strings.Join(parts[:1], " ")
		attrStr = strings.Trim(attrStr, "()")
		if attrStr != "" {
			attributes = strings.Fields(attrStr)
		}
	}
	
	// Extract delimiter and name
	delimiter := strings.Trim(parts[len(parts)-2], `"`)
	name := strings.Trim(parts[len(parts)-1], `"`)
	
	return &IMAPMailbox{
		Name:       name,
		Attributes: attributes,
		Delimiter:  delimiter,
	}
}

func (imap *IMAPAnalyzer) parseStatusResponse(parts []string) map[string]interface{} {
	status := make(map[string]interface{})
	
	// STATUS response format: (MESSAGES nn RECENT nn UIDNEXT nn UIDVALIDITY nn UNSEEN nn)
	statusStr := strings.Join(parts, " ")
	statusStr = strings.Trim(statusStr, "()")
	
	statusParts := strings.Fields(statusStr)
	for i := 0; i < len(statusParts)-1; i += 2 {
		key := strings.ToLower(statusParts[i])
		if i+1 < len(statusParts) {
			if val, err := strconv.Atoi(statusParts[i+1]); err == nil {
				status[key] = val
			}
		}
	}
	
	return status
}

func (imap *IMAPAnalyzer) parseFetchResponse(parts []string) map[string]interface{} {
	fetchData := make(map[string]interface{})
	
	// FETCH response is complex, simplified parsing
	responseStr := strings.Join(parts, " ")
	
	// Look for common FETCH items
	if strings.Contains(responseStr, "RFC822.SIZE") {
		re := regexp.MustCompile(`RFC822\.SIZE\s+(\d+)`)
		if matches := re.FindStringSubmatch(responseStr); len(matches) > 1 {
			if size, err := strconv.ParseInt(matches[1], 10, 64); err == nil {
				fetchData["size"] = size
			}
		}
	}
	
	if strings.Contains(responseStr, "ENVELOPE") {
		fetchData["envelope"] = true
	}
	
	if strings.Contains(responseStr, "BODY") {
		fetchData["body"] = true
	}
	
	if strings.Contains(responseStr, "FLAGS") {
		re := regexp.MustCompile(`FLAGS\s+\(([^)]+)\)`)
		if matches := re.FindStringSubmatch(responseStr); len(matches) > 1 {
			flags := strings.Fields(matches[1])
			fetchData["flags"] = flags
		}
	}
	
	return fetchData
}

func (imap *IMAPAnalyzer) findOrCreateMailbox(session *IMAPSession, name string) *IMAPMailbox {
	// Find existing mailbox
	for i, mailbox := range session.Mailboxes {
		if mailbox.Name == name {
			return &session.Mailboxes[i]
		}
	}
	
	// Create new mailbox
	mailbox := IMAPMailbox{
		Name: name,
	}
	session.Mailboxes = append(session.Mailboxes, mailbox)
	return &session.Mailboxes[len(session.Mailboxes)-1]
}

func (imap *IMAPAnalyzer) createOrUpdateMessage(session *IMAPSession, seqNum int, fetchData map[string]interface{}) *IMAPMessage {
	// Find existing message
	for i, msg := range session.Messages {
		if msg.SequenceNum == seqNum {
			// Update existing message
			if size, ok := fetchData["size"].(int64); ok {
				session.Messages[i].Size = size
			}
			if flags, ok := fetchData["flags"].([]string); ok {
				session.Messages[i].Flags = flags
			}
			session.Messages[i].Fetched = true
			return &session.Messages[i]
		}
	}
	
	// Create new message
	message := IMAPMessage{
		SequenceNum: seqNum,
		Mailbox:     "",
		Headers:     make(map[string]string),
		Flags:       make([]string, 0),
		Attachments: make([]EmailAttachment, 0),
		Timestamp:   time.Now(),
		Fetched:     true,
	}
	
	if session.SelectedMailbox != nil {
		message.Mailbox = session.SelectedMailbox.Name
	}
	
	if size, ok := fetchData["size"].(int64); ok {
		message.Size = size
	}
	if flags, ok := fetchData["flags"].([]string); ok {
		message.Flags = flags
	}
	
	session.Messages = append(session.Messages, message)
	return &session.Messages[len(session.Messages)-1]
}

// GetActiveSessions returns all active IMAP sessions
func (imap *IMAPAnalyzer) GetActiveSessions() []*IMAPSession {
	var sessions []*IMAPSession
	cutoff := time.Now().Add(-30 * time.Minute)
	
	for key, session := range imap.sessions {
		if session.LastActivity.After(cutoff) {
			sessions = append(sessions, session)
		} else {
			delete(imap.sessions, key)
		}
	}
	
	return sessions
}

// GetSessionStats returns IMAP session statistics
func (imap *IMAPAnalyzer) GetSessionStats() map[string]interface{} {
	activeSessions := imap.GetActiveSessions()
	
	stats := map[string]interface{}{
		"active_sessions":        len(activeSessions),
		"authenticated_sessions": 0,
		"total_mailboxes":       0,
		"total_messages":        0,
		"fetched_messages":      0,
		"tls_sessions":          0,
		"total_message_size":    int64(0),
	}
	
	for _, session := range activeSessions {
		if session.Authenticated {
			stats["authenticated_sessions"] = stats["authenticated_sessions"].(int) + 1
		}
		
		if session.TLSEnabled {
			stats["tls_sessions"] = stats["tls_sessions"].(int) + 1
		}
		
		stats["total_mailboxes"] = stats["total_mailboxes"].(int) + len(session.Mailboxes)
		stats["total_messages"] = stats["total_messages"].(int) + len(session.Messages)
		
		for _, message := range session.Messages {
			if message.Fetched {
				stats["fetched_messages"] = stats["fetched_messages"].(int) + 1
			}
			stats["total_message_size"] = stats["total_message_size"].(int64) + message.Size
		}
	}
	
	return stats
}

// ExtractMessages returns all messages extracted from IMAP sessions
func (imap *IMAPAnalyzer) ExtractMessages() []IMAPMessage {
	var messages []IMAPMessage
	
	for _, session := range imap.sessions {
		messages = append(messages, session.Messages...)
	}
	
	return messages
}