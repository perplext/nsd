package protocols

import (
	"bufio"
	"encoding/base64"
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

// SMTPAnalyzer analyzes SMTP protocol traffic
type SMTPAnalyzer struct {
	BaseAnalyzer
	sessions map[string]*SMTPSession
}

// SMTPSession represents an active SMTP session
type SMTPSession struct {
	ID               string
	ClientIP         net.IP
	ServerIP         net.IP
	Port             uint16
	ServerName       string
	ClientName       string
	AuthMethod       string
	Username         string
	Commands         []SMTPCommand
	Emails           []SMTPEmail
	Extensions       []string
	StartTime        time.Time
	LastActivity     time.Time
	Authenticated    bool
	TLSEnabled       bool
	ESMTPEnabled     bool
	CurrentEmail     *SMTPEmail
	State            SMTPState
}

// SMTPState represents the state of an SMTP connection
type SMTPState int

const (
	SMTPStateInit SMTPState = iota
	SMTPStateGreeting
	SMTPStateAuthenticated
	SMTPStateMailTransaction
	SMTPStateData
	SMTPStateQuit
)

// SMTPCommand represents an SMTP command
type SMTPCommand struct {
	Command   string
	Arguments string
	Response  string
	Code      int
	Timestamp time.Time
}

// SMTPEmail represents an email being sent via SMTP
type SMTPEmail struct {
	ID          string
	MessageID   string
	From        string
	To          []string
	CC          []string
	BCC         []string
	Subject     string
	Date        time.Time
	Size        int64
	Headers     map[string]string
	Body        string
	Attachments []EmailAttachment
	Timestamp   time.Time
	Complete    bool
}

// NewSMTPAnalyzer creates a new SMTP analyzer
func NewSMTPAnalyzer() ProtocolAnalyzer {
	return &SMTPAnalyzer{
		BaseAnalyzer: BaseAnalyzer{
			protocolName: "SMTP",
			ports:        []uint16{25, 465, 587}, // SMTP, SMTPS, Submission
		},
		sessions: make(map[string]*SMTPSession),
	}
}

// AnalyzeStream analyzes an SMTP stream
func (smtp *SMTPAnalyzer) AnalyzeStream(flow gopacket.Flow, reader *tcpreader.ReaderStream) []ProtocolEvent {
	var events []ProtocolEvent
	buf := bufio.NewReader(reader)
	
	// Create session key
	sessionKey := fmt.Sprintf("%s->%s", flow.Src().String(), flow.Dst().String())
	
	// Get or create session
	session := smtp.getOrCreateSession(sessionKey, flow)
	
	// Analyze SMTP protocol
	events = append(events, smtp.analyzeSMTPStream(session, buf)...)
	
	return events
}

// IsProtocolTraffic determines if data is SMTP traffic
func (smtp *SMTPAnalyzer) IsProtocolTraffic(data []byte) bool {
	dataStr := strings.ToUpper(string(data))
	
	// Check for SMTP server greeting
	if strings.HasPrefix(dataStr, "220 ") {
		return true
	}
	
	// Check for common SMTP commands
	smtpCommands := []string{"HELO ", "EHLO ", "MAIL FROM:", "RCPT TO:", "DATA", "RSET", "VRFY ", "EXPN ", "HELP", "NOOP", "QUIT", "AUTH ", "STARTTLS"}
	for _, cmd := range smtpCommands {
		if strings.HasPrefix(dataStr, cmd) {
			return true
		}
	}
	
	// Check for SMTP response codes
	if len(dataStr) >= 3 {
		code := dataStr[:3]
		if _, err := strconv.Atoi(code); err == nil {
			return true
		}
	}
	
	return false
}

func (smtp *SMTPAnalyzer) getOrCreateSession(sessionKey string, flow gopacket.Flow) *SMTPSession {
	if session, exists := smtp.sessions[sessionKey]; exists {
		session.LastActivity = time.Now()
		return session
	}
	
	session := &SMTPSession{
		ID:           fmt.Sprintf("smtp_%d", time.Now().UnixNano()),
		ClientIP:     net.ParseIP(flow.Src().String()),
		ServerIP:     net.ParseIP(flow.Dst().String()),
		Port:         uint16(flow.Dst().FastHash()),
		Commands:     make([]SMTPCommand, 0),
		Emails:       make([]SMTPEmail, 0),
		Extensions:   make([]string, 0),
		StartTime:    time.Now(),
		LastActivity: time.Now(),
		State:        SMTPStateInit,
	}
	
	smtp.sessions[sessionKey] = session
	return session
}

func (smtp *SMTPAnalyzer) analyzeSMTPStream(session *SMTPSession, reader *bufio.Reader) []ProtocolEvent {
	var events []ProtocolEvent
	var isDataMode bool
	var emailData []string
	
	for {
		line, err := ReadLine(reader)
		if err != nil {
			break
		}
		
		if line == "" {
			continue
		}
		
		// Handle DATA mode
		if isDataMode {
			if line == "." {
				// End of email data
				isDataMode = false
				event := smtp.processEmailData(session, emailData)
				if event != nil {
					events = append(events, *event)
				}
				emailData = []string{}
			} else {
				// Collect email data
				emailData = append(emailData, line)
			}
			continue
		}
		
		// Determine if this is a command or response
		if smtp.isCommand(line) {
			event := smtp.processCommand(session, line)
			if event != nil {
				events = append(events, *event)
				
				// Check if entering DATA mode
				if strings.ToUpper(strings.TrimSpace(line)) == "DATA" {
					// Wait for 354 response, then enter data mode
				}
			}
		} else if smtp.isResponse(line) {
			event := smtp.processResponse(session, line, &isDataMode)
			if event != nil {
				events = append(events, *event)
			}
		}
	}
	
	return events
}

func (smtp *SMTPAnalyzer) isCommand(line string) bool {
	// SMTP commands are typically at the start of the line
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return false
	}
	
	command := strings.ToUpper(parts[0])
	smtpCommands := []string{"HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET", "VRFY", "EXPN", "HELP", "NOOP", "QUIT", "AUTH", "STARTTLS"}
	
	for _, cmd := range smtpCommands {
		if strings.HasPrefix(command, cmd) {
			return true
		}
	}
	
	return false
}

func (smtp *SMTPAnalyzer) isResponse(line string) bool {
	// SMTP responses start with a 3-digit code
	if len(line) < 3 {
		return false
	}
	
	code := line[:3]
	_, err := strconv.Atoi(code)
	return err == nil
}

func (smtp *SMTPAnalyzer) processCommand(session *SMTPSession, line string) *ProtocolEvent {
	parts := strings.SplitN(line, " ", 2)
	command := strings.ToUpper(parts[0])
	var arguments string
	if len(parts) > 1 {
		arguments = parts[1]
	}
	
	// Add to session commands
	smtpCmd := SMTPCommand{
		Command:   command,
		Arguments: arguments,
		Timestamp: time.Now(),
	}
	session.Commands = append(session.Commands, smtpCmd)
	
	// Create event
	event := &ProtocolEvent{
		ID:        GenerateEventID("SMTP"),
		Protocol:  "SMTP",
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
	case "HELO", "EHLO":
		session.ClientName = arguments
		session.State = SMTPStateGreeting
		if command == "EHLO" {
			session.ESMTPEnabled = true
		}
		event.Data["client_name"] = arguments
		event.Data["esmtp"] = command == "EHLO"
		
	case "AUTH":
		event.EventType = EventTypeAuthentication
		authParts := strings.Fields(arguments)
		if len(authParts) > 0 {
			session.AuthMethod = authParts[0]
			event.Data["auth_method"] = authParts[0]
		}
		
	case "MAIL":
		// MAIL FROM:<sender>
		sender := smtp.extractEmailAddress(arguments)
		if sender != "" {
			session.CurrentEmail = &SMTPEmail{
				ID:          fmt.Sprintf("email_%d", time.Now().UnixNano()),
				From:        sender,
				To:          make([]string, 0),
				CC:          make([]string, 0),
				BCC:         make([]string, 0),
				Headers:     make(map[string]string),
				Attachments: make([]EmailAttachment, 0),
				Timestamp:   time.Now(),
			}
			session.State = SMTPStateMailTransaction
			event.EventType = EventTypeEmail
			event.Data["sender"] = sender
		}
		
	case "RCPT":
		// RCPT TO:<recipient>
		recipient := smtp.extractEmailAddress(arguments)
		if recipient != "" && session.CurrentEmail != nil {
			session.CurrentEmail.To = append(session.CurrentEmail.To, recipient)
			event.EventType = EventTypeEmail
			event.Data["recipient"] = recipient
		}
		
	case "DATA":
		session.State = SMTPStateData
		event.EventType = EventTypeEmail
		event.Data["starting_data"] = true
		
	case "RSET":
		session.CurrentEmail = nil
		session.State = SMTPStateGreeting
		event.Data["reset"] = true
		
	case "QUIT":
		session.State = SMTPStateQuit
		event.EventType = EventTypeDisconnection
		
	case "STARTTLS":
		event.Data["tls_requested"] = true
	}
	
	return event
}

func (smtp *SMTPAnalyzer) processResponse(session *SMTPSession, line string, isDataMode *bool) *ProtocolEvent {
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
		ID:        GenerateEventID("SMTP"),
		Protocol:  "SMTP",
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
		// Service ready
		event.EventType = EventTypeConnection
		session.ServerName = smtp.extractServerName(message)
		event.Data["server_name"] = session.ServerName
		
	case code == 250:
		// Command completed successfully
		if len(session.Commands) > 0 {
			lastCmd := session.Commands[len(session.Commands)-1]
			
			switch lastCmd.Command {
			case "EHLO":
				// Extract ESMTP extensions
				if strings.Contains(message, "AUTH") {
					session.Extensions = append(session.Extensions, "AUTH")
				}
				if strings.Contains(message, "STARTTLS") {
					session.Extensions = append(session.Extensions, "STARTTLS")
				}
				event.Data["extensions"] = session.Extensions
				
			case "AUTH":
				session.Authenticated = true
				event.EventType = EventTypeAuthentication
				event.Data["auth_successful"] = true
				
			case "STARTTLS":
				session.TLSEnabled = true
				event.Data["tls_enabled"] = true
			}
		}
		
	case code == 354:
		// Start mail input
		*isDataMode = true
		event.EventType = EventTypeEmail
		event.Data["data_mode"] = true
		
	case code == 535:
		// Authentication failed
		event.EventType = EventTypeAuthentication
		event.Data["auth_failed"] = true
		
	case code >= 400:
		// Error responses
		event.EventType = EventTypeError
		event.Data["error"] = true
	}
	
	return event
}

func (smtp *SMTPAnalyzer) processEmailData(session *SMTPSession, data []string) *ProtocolEvent {
	if session.CurrentEmail == nil {
		return nil
	}
	
	// Join all data lines
	emailContent := strings.Join(data, "\n")
	
	// Parse email headers and body
	smtp.parseEmailContent(session.CurrentEmail, emailContent)
	
	// Add to session emails
	session.CurrentEmail.Complete = true
	session.Emails = append(session.Emails, *session.CurrentEmail)
	
	event := &ProtocolEvent{
		ID:        GenerateEventID("SMTP"),
		Protocol:  "SMTP",
		EventType: EventTypeEmail,
		Data: map[string]interface{}{
			"session_id":   session.ID,
			"email_id":     session.CurrentEmail.ID,
			"from":         session.CurrentEmail.From,
			"to":           session.CurrentEmail.To,
			"subject":      session.CurrentEmail.Subject,
			"size":         session.CurrentEmail.Size,
			"attachments":  len(session.CurrentEmail.Attachments),
		},
	}
	
	// Reset current email
	session.CurrentEmail = nil
	session.State = SMTPStateGreeting
	
	return event
}

func (smtp *SMTPAnalyzer) extractEmailAddress(text string) string {
	// Extract email from MAIL FROM:<email> or RCPT TO:<email>
	re := regexp.MustCompile(`<([^>]+)>`)
	matches := re.FindStringSubmatch(text)
	if len(matches) > 1 {
		return matches[1]
	}
	
	// Fallback to simple extraction
	parts := strings.Fields(text)
	for _, part := range parts {
		if strings.Contains(part, "@") {
			return strings.Trim(part, "<>")
		}
	}
	
	return ""
}

func (smtp *SMTPAnalyzer) extractServerName(greeting string) string {
	// Extract server name from greeting message
	parts := strings.Fields(greeting)
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

func (smtp *SMTPAnalyzer) parseEmailContent(email *SMTPEmail, content string) {
	// Split headers and body
	parts := strings.SplitN(content, "\n\n", 2)
	if len(parts) < 2 {
		return
	}
	
	headerText := parts[0]
	email.Body = parts[1]
	email.Size = int64(len(content))
	
	// Parse headers
	headerLines := strings.Split(headerText, "\n")
	for i, line := range headerLines {
		if line == "" {
			continue
		}
		
		// Handle folded headers (RFC 5322)
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if i > 0 {
				// Append to previous header
				continue
			}
		}
		
		headerParts := strings.SplitN(line, ":", 2)
		if len(headerParts) == 2 {
			key := strings.ToLower(strings.TrimSpace(headerParts[0]))
			value := strings.TrimSpace(headerParts[1])
			email.Headers[key] = value
			
			// Extract common fields
			switch key {
			case "subject":
				email.Subject = smtp.decodeHeader(value)
			case "message-id":
				email.MessageID = value
			case "date":
				if date, err := mail.ParseDate(value); err == nil {
					email.Date = date
				}
			case "cc":
				email.CC = smtp.parseAddressList(value)
			case "bcc":
				email.BCC = smtp.parseAddressList(value)
			}
		}
	}
	
	// Extract attachments
	email.Attachments = smtp.extractEmailAttachments(content)
}

func (smtp *SMTPAnalyzer) decodeHeader(header string) string {
	// Simple RFC 2047 decoding for encoded headers
	if strings.Contains(header, "=?") && strings.Contains(header, "?=") {
		// This is a simplified decoder - full implementation would be more complex
		re := regexp.MustCompile(`=\?([^?]+)\?([BQbq])\?([^?]+)\?=`)
		return re.ReplaceAllStringFunc(header, func(match string) string {
			parts := re.FindStringSubmatch(match)
			if len(parts) != 4 {
				return match
			}
			
			encoding := strings.ToUpper(parts[2])
			encoded := parts[3]
			
			switch encoding {
			case "B":
				if decoded, err := base64.StdEncoding.DecodeString(encoded); err == nil {
					return string(decoded)
				}
			case "Q":
				// Quoted-printable decoding (simplified)
				decoded := strings.ReplaceAll(encoded, "_", " ")
				return decoded
			}
			
			return match
		})
	}
	
	return header
}

func (smtp *SMTPAnalyzer) parseAddressList(addresses string) []string {
	// Simple address list parsing
	addrs := strings.Split(addresses, ",")
	var result []string
	
	for _, addr := range addrs {
		addr = strings.TrimSpace(addr)
		if addr != "" {
			result = append(result, addr)
		}
	}
	
	return result
}

func (smtp *SMTPAnalyzer) extractEmailAttachments(content string) []EmailAttachment {
	var attachments []EmailAttachment
	
	// Look for MIME attachments
	if strings.Contains(content, "Content-Disposition: attachment") {
		// Simple attachment detection
		re := regexp.MustCompile(`(?i)content-disposition:\s*attachment[^;]*;\s*filename[^=]*=\s*"?([^"\n\r]+)"?`)
		matches := re.FindAllStringSubmatch(content, -1)
		
		for _, match := range matches {
			if len(match) > 1 {
				attachment := EmailAttachment{
					Filename: strings.TrimSpace(match[1]),
				}
				
				// Try to extract content type
				ctRe := regexp.MustCompile(`(?i)content-type:\s*([^;\n\r]+)`)
				if ctMatches := ctRe.FindStringSubmatch(content); len(ctMatches) > 1 {
					attachment.ContentType = strings.TrimSpace(ctMatches[1])
				}
				
				attachments = append(attachments, attachment)
			}
		}
	}
	
	return attachments
}

// GetActiveSessions returns all active SMTP sessions
func (smtp *SMTPAnalyzer) GetActiveSessions() []*SMTPSession {
	var sessions []*SMTPSession
	cutoff := time.Now().Add(-30 * time.Minute)
	
	for key, session := range smtp.sessions {
		if session.LastActivity.After(cutoff) {
			sessions = append(sessions, session)
		} else {
			delete(smtp.sessions, key)
		}
	}
	
	return sessions
}

// GetSessionStats returns SMTP session statistics
func (smtp *SMTPAnalyzer) GetSessionStats() map[string]interface{} {
	activeSessions := smtp.GetActiveSessions()
	
	stats := map[string]interface{}{
		"active_sessions":        len(activeSessions),
		"authenticated_sessions": 0,
		"tls_sessions":          0,
		"total_emails":          0,
		"total_attachments":     0,
		"total_email_size":      int64(0),
	}
	
	for _, session := range activeSessions {
		if session.Authenticated {
			stats["authenticated_sessions"] = stats["authenticated_sessions"].(int) + 1
		}
		
		if session.TLSEnabled {
			stats["tls_sessions"] = stats["tls_sessions"].(int) + 1
		}
		
		stats["total_emails"] = stats["total_emails"].(int) + len(session.Emails)
		
		for _, email := range session.Emails {
			stats["total_email_size"] = stats["total_email_size"].(int64) + email.Size
			stats["total_attachments"] = stats["total_attachments"].(int) + len(email.Attachments)
		}
	}
	
	return stats
}

// ExtractEmails returns all emails sent via SMTP
func (smtp *SMTPAnalyzer) ExtractEmails() []SMTPEmail {
	var emails []SMTPEmail
	
	for _, session := range smtp.sessions {
		emails = append(emails, session.Emails...)
	}
	
	return emails
}