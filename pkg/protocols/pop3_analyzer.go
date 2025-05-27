package protocols

import (
	"bufio"
	"fmt"
	"net"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// POP3Analyzer analyzes POP3 protocol traffic
type POP3Analyzer struct {
	BaseAnalyzer
	sessions map[string]*POP3Session
}

// POP3Session represents an active POP3 session
type POP3Session struct {
	ID               string
	ClientIP         net.IP
	ServerIP         net.IP
	Port             uint16
	Username         string
	AuthMethod       string
	Commands         []POP3Command
	Emails           []EmailMessage
	Statistics       POP3Stats
	StartTime        time.Time
	LastActivity     time.Time
	Authenticated    bool
	TransactionState bool
	UpdateState      bool
	CurrentEmail     *EmailMessage
}

// POP3Command represents a POP3 command
type POP3Command struct {
	Command   string
	Arguments []string
	Response  string
	Success   bool
	Timestamp time.Time
}

// EmailMessage represents an email message retrieved via POP3
type EmailMessage struct {
	ID          string
	MessageID   string
	Subject     string
	From        string
	To          []string
	CC          []string
	BCC         []string
	Date        time.Time
	Size        int64
	Headers     map[string]string
	Body        string
	Attachments []EmailAttachment
	Retrieved   bool
	Deleted     bool
	Timestamp   time.Time
}

// EmailAttachment represents an email attachment
type EmailAttachment struct {
	Filename    string
	ContentType string
	Size        int64
	Content     []byte
	Encoding    string
}

// POP3Stats represents POP3 session statistics
type POP3Stats struct {
	MessageCount   int
	TotalSize      int64
	RetrievedCount int
	DeletedCount   int
	BytesReceived  int64
}

// NewPOP3Analyzer creates a new POP3 analyzer
func NewPOP3Analyzer() ProtocolAnalyzer {
	return &POP3Analyzer{
		BaseAnalyzer: BaseAnalyzer{
			protocolName: "POP3",
			ports:        []uint16{110, 995}, // POP3 and POP3S
		},
		sessions: make(map[string]*POP3Session),
	}
}

// AnalyzeStream analyzes a POP3 stream
func (pop3 *POP3Analyzer) AnalyzeStream(flow gopacket.Flow, reader *tcpreader.ReaderStream) []ProtocolEvent {
	var events []ProtocolEvent
	buf := bufio.NewReader(reader)
	
	// Create session key
	sessionKey := fmt.Sprintf("%s->%s", flow.Src().String(), flow.Dst().String())
	
	// Get or create session
	session := pop3.getOrCreateSession(sessionKey, flow)
	
	// Analyze POP3 protocol
	events = append(events, pop3.analyzePOP3Stream(session, buf)...)
	
	return events
}

// IsProtocolTraffic determines if data is POP3 traffic
func (pop3 *POP3Analyzer) IsProtocolTraffic(data []byte) bool {
	dataStr := strings.ToUpper(string(data))
	
	// Check for POP3 server greeting
	if strings.HasPrefix(dataStr, "+OK ") {
		return true
	}
	
	// Check for common POP3 commands
	pop3Commands := []string{"USER ", "PASS ", "STAT", "LIST", "RETR ", "DELE ", "NOOP", "RSET", "QUIT", "TOP ", "UIDL"}
	for _, cmd := range pop3Commands {
		if strings.HasPrefix(dataStr, cmd) {
			return true
		}
	}
	
	// Check for POP3 error responses
	if strings.HasPrefix(dataStr, "-ERR ") {
		return true
	}
	
	return false
}

func (pop3 *POP3Analyzer) getOrCreateSession(sessionKey string, flow gopacket.Flow) *POP3Session {
	if session, exists := pop3.sessions[sessionKey]; exists {
		session.LastActivity = time.Now()
		return session
	}
	
	session := &POP3Session{
		ID:           fmt.Sprintf("pop3_%d", time.Now().UnixNano()),
		ClientIP:     net.ParseIP(flow.Src().String()),
		ServerIP:     net.ParseIP(flow.Dst().String()),
		Port:         uint16(flow.Dst().FastHash()),
		Commands:     make([]POP3Command, 0),
		Emails:       make([]EmailMessage, 0),
		StartTime:    time.Now(),
		LastActivity: time.Now(),
		Statistics:   POP3Stats{},
	}
	
	pop3.sessions[sessionKey] = session
	return session
}

func (pop3 *POP3Analyzer) analyzePOP3Stream(session *POP3Session, reader *bufio.Reader) []ProtocolEvent {
	var events []ProtocolEvent
	var isMultilineResponse bool
	var multilineData []string
	var currentCommand *POP3Command
	
	for {
		line, err := ReadLine(reader)
		if err != nil {
			break
		}
		
		if line == "" {
			continue
		}
		
		// Handle multi-line responses
		if isMultilineResponse {
			if line == "." {
				// End of multi-line response
				isMultilineResponse = false
				
				// Process collected data
				event := pop3.processMultilineResponse(session, currentCommand, multilineData)
				if event != nil {
					events = append(events, *event)
				}
				
				multilineData = []string{}
				currentCommand = nil
			} else {
				// Collect multi-line data
				multilineData = append(multilineData, line)
			}
			continue
		}
		
		// Determine if this is a command or response
		if pop3.isCommand(line) {
			event := pop3.processCommand(session, line)
			if event != nil {
				events = append(events, *event)
				
				// Check if this command expects a multi-line response
				command := strings.Fields(strings.ToUpper(line))[0]
				if command == "RETR" || command == "TOP" || command == "LIST" || command == "UIDL" {
					currentCommand = &session.Commands[len(session.Commands)-1]
				}
			}
		} else if pop3.isResponse(line) {
			event := pop3.processResponse(session, line)
			if event != nil {
				events = append(events, *event)
				
				// Check if response indicates start of multi-line data
				if strings.HasPrefix(line, "+OK") && currentCommand != nil {
					cmd := strings.ToUpper(currentCommand.Command)
					if cmd == "RETR" || cmd == "TOP" || cmd == "LIST" || cmd == "UIDL" {
						isMultilineResponse = true
					}
				}
			}
		}
	}
	
	return events
}

func (pop3 *POP3Analyzer) isCommand(line string) bool {
	// POP3 commands are typically 3-4 characters
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return false
	}
	
	command := strings.ToUpper(parts[0])
	pop3Commands := []string{"USER", "PASS", "STAT", "LIST", "RETR", "DELE", "NOOP", "RSET", "QUIT", "TOP", "UIDL", "APOP", "AUTH"}
	
	for _, cmd := range pop3Commands {
		if command == cmd {
			return true
		}
	}
	
	return false
}

func (pop3 *POP3Analyzer) isResponse(line string) bool {
	return strings.HasPrefix(line, "+OK") || strings.HasPrefix(line, "-ERR")
}

func (pop3 *POP3Analyzer) processCommand(session *POP3Session, line string) *ProtocolEvent {
	parts := strings.Fields(line)
	command := strings.ToUpper(parts[0])
	var arguments []string
	if len(parts) > 1 {
		arguments = parts[1:]
	}
	
	// Add to session commands
	pop3Cmd := POP3Command{
		Command:   command,
		Arguments: arguments,
		Timestamp: time.Now(),
	}
	session.Commands = append(session.Commands, pop3Cmd)
	
	// Create event
	event := &ProtocolEvent{
		ID:        GenerateEventID("POP3"),
		Protocol:  "POP3",
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
		if len(arguments) > 0 {
			session.Username = arguments[0]
			event.Username = arguments[0]
			event.EventType = EventTypeAuthentication
		}
		
	case "PASS":
		event.EventType = EventTypeAuthentication
		event.Data["password_provided"] = true
		
	case "APOP":
		if len(arguments) > 0 {
			session.Username = arguments[0]
			session.AuthMethod = "APOP"
			event.Username = arguments[0]
			event.EventType = EventTypeAuthentication
			event.Data["auth_method"] = "APOP"
		}
		
	case "STAT":
		event.Data["requesting_stats"] = true
		
	case "LIST":
		event.Data["requesting_list"] = true
		if len(arguments) > 0 {
			event.Data["message_number"] = arguments[0]
		}
		
	case "RETR":
		if len(arguments) > 0 {
			event.EventType = EventTypeEmail
			event.Data["retrieving_message"] = arguments[0]
		}
		
	case "DELE":
		if len(arguments) > 0 {
			event.Data["deleting_message"] = arguments[0]
		}
		
	case "TOP":
		if len(arguments) >= 2 {
			event.EventType = EventTypeEmail
			event.Data["message_number"] = arguments[0]
			event.Data["lines_requested"] = arguments[1]
		}
		
	case "QUIT":
		event.EventType = EventTypeDisconnection
		session.UpdateState = true
	}
	
	return event
}

func (pop3 *POP3Analyzer) processResponse(session *POP3Session, line string) *ProtocolEvent {
	success := strings.HasPrefix(line, "+OK")
	message := ""
	if len(line) > 4 {
		message = line[4:]
	}
	
	// Update last command with response
	if len(session.Commands) > 0 {
		lastCmd := &session.Commands[len(session.Commands)-1]
		lastCmd.Response = line
		lastCmd.Success = success
	}
	
	event := &ProtocolEvent{
		ID:        GenerateEventID("POP3"),
		Protocol:  "POP3",
		EventType: EventTypeCommand,
		Response:  line,
		Status:    fmt.Sprintf("%t", success),
		Data: map[string]interface{}{
			"session_id": session.ID,
			"success":    success,
			"message":    message,
		},
	}
	
	// Handle specific responses
	if success {
		if len(session.Commands) > 0 {
			lastCmd := session.Commands[len(session.Commands)-1]
			
			switch lastCmd.Command {
			case "USER":
				event.EventType = EventTypeAuthentication
				event.Username = session.Username
				
			case "PASS", "APOP":
				if success {
					session.Authenticated = true
					session.TransactionState = true
					event.EventType = EventTypeAuthentication
					event.Username = session.Username
					event.Data["login_successful"] = true
				}
				
			case "STAT":
				// Parse message count and total size
				stats := pop3.parseStatResponse(message)
				if stats != nil {
					session.Statistics.MessageCount = stats.MessageCount
					session.Statistics.TotalSize = stats.TotalSize
					event.Data["message_count"] = stats.MessageCount
					event.Data["total_size"] = stats.TotalSize
				}
				
			case "QUIT":
				event.EventType = EventTypeDisconnection
			}
		}
	} else {
		// Error response
		event.EventType = EventTypeError
		
		if len(session.Commands) > 0 {
			lastCmd := session.Commands[len(session.Commands)-1]
			if lastCmd.Command == "PASS" || lastCmd.Command == "APOP" {
				event.EventType = EventTypeAuthentication
				event.Username = session.Username
				event.Data["login_failed"] = true
			}
		}
	}
	
	return event
}

func (pop3 *POP3Analyzer) processMultilineResponse(session *POP3Session, command *POP3Command, data []string) *ProtocolEvent {
	if command == nil {
		return nil
	}
	
	event := &ProtocolEvent{
		ID:        GenerateEventID("POP3"),
		Protocol:  "POP3",
		EventType: EventTypeEmail,
		Data: map[string]interface{}{
			"session_id": session.ID,
			"command":    command.Command,
			"data_lines": len(data),
		},
	}
	
	switch command.Command {
	case "RETR":
		// Full email retrieval
		email := pop3.parseEmailMessage(data)
		if email != nil {
			email.Retrieved = true
			session.Emails = append(session.Emails, *email)
			session.Statistics.RetrievedCount++
			
			event.Data["email_id"] = email.ID
			event.Data["subject"] = email.Subject
			event.Data["from"] = email.From
			event.Data["size"] = email.Size
			event.Data["attachments"] = len(email.Attachments)
		}
		
	case "TOP":
		// Email headers only
		email := pop3.parseEmailHeaders(data)
		if email != nil {
			event.Data["subject"] = email.Subject
			event.Data["from"] = email.From
			event.Data["headers_only"] = true
		}
		
	case "LIST":
		// Message list
		messages := pop3.parseMessageList(data)
		event.Data["messages"] = len(messages)
		
	case "UIDL":
		// Unique ID list
		uidList := pop3.parseUIDList(data)
		event.Data["unique_ids"] = len(uidList)
	}
	
	return event
}

func (pop3 *POP3Analyzer) parseStatResponse(message string) *POP3Stats {
	// STAT response format: "+OK nn mm" where nn is count and mm is size
	parts := strings.Fields(message)
	if len(parts) < 2 {
		return nil
	}
	
	count, err1 := strconv.Atoi(parts[0])
	size, err2 := strconv.ParseInt(parts[1], 10, 64)
	
	if err1 != nil || err2 != nil {
		return nil
	}
	
	return &POP3Stats{
		MessageCount: count,
		TotalSize:    size,
	}
}

func (pop3 *POP3Analyzer) parseEmailMessage(lines []string) *EmailMessage {
	if len(lines) == 0 {
		return nil
	}
	
	// Join all lines to create full message
	fullMessage := strings.Join(lines, "\n")
	
	// Parse email headers and body
	email := &EmailMessage{
		ID:          fmt.Sprintf("email_%d", time.Now().UnixNano()),
		Headers:     make(map[string]string),
		Timestamp:   time.Now(),
		Attachments: make([]EmailAttachment, 0),
	}
	
	// Split headers and body
	parts := strings.SplitN(fullMessage, "\n\n", 2)
	if len(parts) < 2 {
		return email
	}
	
	headerLines := strings.Split(parts[0], "\n")
	email.Body = parts[1]
	email.Size = int64(len(fullMessage))
	
	// Parse headers
	for _, line := range headerLines {
		if line == "" {
			continue
		}
		
		// Handle folded headers
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue // Skip folded lines for now
		}
		
		headerParts := strings.SplitN(line, ":", 2)
		if len(headerParts) == 2 {
			key := strings.ToLower(strings.TrimSpace(headerParts[0]))
			value := strings.TrimSpace(headerParts[1])
			email.Headers[key] = value
			
			// Extract common fields
			switch key {
			case "subject":
				email.Subject = value
			case "from":
				email.From = value
			case "to":
				email.To = pop3.parseAddressList(value)
			case "cc":
				email.CC = pop3.parseAddressList(value)
			case "bcc":
				email.BCC = pop3.parseAddressList(value)
			case "message-id":
				email.MessageID = value
			case "date":
				if date, err := mail.ParseDate(value); err == nil {
					email.Date = date
				}
			}
		}
	}
	
	// Extract attachments (simplified)
	email.Attachments = pop3.extractAttachments(email.Body)
	
	return email
}

func (pop3 *POP3Analyzer) parseEmailHeaders(lines []string) *EmailMessage {
	email := &EmailMessage{
		ID:        fmt.Sprintf("header_%d", time.Now().UnixNano()),
		Headers:   make(map[string]string),
		Timestamp: time.Now(),
	}
	
	for _, line := range lines {
		if line == "" {
			continue
		}
		
		headerParts := strings.SplitN(line, ":", 2)
		if len(headerParts) == 2 {
			key := strings.ToLower(strings.TrimSpace(headerParts[0]))
			value := strings.TrimSpace(headerParts[1])
			email.Headers[key] = value
			
			switch key {
			case "subject":
				email.Subject = value
			case "from":
				email.From = value
			case "message-id":
				email.MessageID = value
			}
		}
	}
	
	return email
}

func (pop3 *POP3Analyzer) parseMessageList(lines []string) []map[string]interface{} {
	var messages []map[string]interface{}
	
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			number, err1 := strconv.Atoi(parts[0])
			size, err2 := strconv.ParseInt(parts[1], 10, 64)
			
			if err1 == nil && err2 == nil {
				messages = append(messages, map[string]interface{}{
					"number": number,
					"size":   size,
				})
			}
		}
	}
	
	return messages
}

func (pop3 *POP3Analyzer) parseUIDList(lines []string) []map[string]interface{} {
	var uidList []map[string]interface{}
	
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			number, err := strconv.Atoi(parts[0])
			if err == nil {
				uidList = append(uidList, map[string]interface{}{
					"number": number,
					"uid":    parts[1],
				})
			}
		}
	}
	
	return uidList
}

func (pop3 *POP3Analyzer) parseAddressList(addresses string) []string {
	// Simple address parsing
	addrs := strings.Split(addresses, ",")
	var result []string
	
	for _, addr := range addrs {
		result = append(result, strings.TrimSpace(addr))
	}
	
	return result
}

func (pop3 *POP3Analyzer) extractAttachments(body string) []EmailAttachment {
	var attachments []EmailAttachment
	
	// Look for Content-Disposition: attachment
	re := regexp.MustCompile(`(?i)content-disposition:\s*attachment[^;]*;\s*filename[^=]*=\s*"?([^"\n\r]+)"?`)
	matches := re.FindAllStringSubmatch(body, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			attachment := EmailAttachment{
				Filename: strings.TrimSpace(match[1]),
			}
			attachments = append(attachments, attachment)
		}
	}
	
	return attachments
}

// GetActiveSessions returns all active POP3 sessions
func (pop3 *POP3Analyzer) GetActiveSessions() []*POP3Session {
	var sessions []*POP3Session
	cutoff := time.Now().Add(-30 * time.Minute)
	
	for key, session := range pop3.sessions {
		if session.LastActivity.After(cutoff) {
			sessions = append(sessions, session)
		} else {
			delete(pop3.sessions, key)
		}
	}
	
	return sessions
}

// GetSessionStats returns POP3 session statistics
func (pop3 *POP3Analyzer) GetSessionStats() map[string]interface{} {
	activeSessions := pop3.GetActiveSessions()
	
	stats := map[string]interface{}{
		"active_sessions":        len(activeSessions),
		"authenticated_sessions": 0,
		"total_emails":          0,
		"retrieved_emails":      0,
		"deleted_emails":        0,
		"total_attachments":     0,
		"total_bytes":           int64(0),
	}
	
	for _, session := range activeSessions {
		if session.Authenticated {
			stats["authenticated_sessions"] = stats["authenticated_sessions"].(int) + 1
		}
		
		stats["total_emails"] = stats["total_emails"].(int) + len(session.Emails)
		stats["retrieved_emails"] = stats["retrieved_emails"].(int) + session.Statistics.RetrievedCount
		stats["deleted_emails"] = stats["deleted_emails"].(int) + session.Statistics.DeletedCount
		stats["total_bytes"] = stats["total_bytes"].(int64) + session.Statistics.TotalSize
		
		for _, email := range session.Emails {
			stats["total_attachments"] = stats["total_attachments"].(int) + len(email.Attachments)
		}
	}
	
	return stats
}

// ExtractEmails returns all emails extracted from POP3 sessions
func (pop3 *POP3Analyzer) ExtractEmails() []EmailMessage {
	var emails []EmailMessage
	
	for _, session := range pop3.sessions {
		emails = append(emails, session.Emails...)
	}
	
	return emails
}