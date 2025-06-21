package alerts

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"time"
)

type AlertLevel int

const (
	AlertInfo AlertLevel = iota
	AlertWarning
	AlertCritical
)

func (l AlertLevel) String() string {
	switch l {
	case AlertInfo:
		return "INFO"
	case AlertWarning:
		return "WARNING"
	case AlertCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

type Alert struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Level       AlertLevel             `json:"level"`
	Timestamp   time.Time              `json:"timestamp"`
	Source      string                 `json:"source"`
	Data        map[string]interface{} `json:"data,omitempty"`
	Resolved    bool                   `json:"resolved"`
}

type AlertRule struct {
	ID          string                          `json:"id"`
	Name        string                          `json:"name"`
	Description string                          `json:"description"`
	Condition   func(data interface{}) bool     `json:"-"`
	Level       AlertLevel                      `json:"level"`
	Enabled     bool                            `json:"enabled"`
	Cooldown    time.Duration                   `json:"cooldown"`
	LastFired   time.Time                       `json:"last_fired"`
}

type NotificationChannel interface {
	Send(alert *Alert) error
	Name() string
}

type AlertManager struct {
	alerts      []Alert
	rules       map[string]*AlertRule
	channels    []NotificationChannel
	mutex       sync.RWMutex
	maxAlerts   int
}

// Email notification channel
type EmailChannel struct {
	SMTPServer string
	Port       int
	Username   string
	Password   string
	From       string
	To         []string
}

func (e *EmailChannel) Name() string {
	return "email"
}

func (e *EmailChannel) Send(alert *Alert) error {
	auth := smtp.PlainAuth("", e.Username, e.Password, e.SMTPServer)
	
	subject := fmt.Sprintf("[NSD Alert - %s] %s", alert.Level.String(), alert.Title)
	body := fmt.Sprintf(`
Alert Details:
- Title: %s
- Level: %s
- Description: %s
- Source: %s
- Timestamp: %s
- Data: %+v
	`, alert.Title, alert.Level.String(), alert.Description, alert.Source, alert.Timestamp.Format(time.RFC3339), alert.Data)
	
	message := fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s", strings.Join(e.To, ","), subject, body)
	
	return smtp.SendMail(
		fmt.Sprintf("%s:%d", e.SMTPServer, e.Port),
		auth,
		e.From,
		e.To,
		[]byte(message),
	)
}

// Webhook notification channel
type WebhookChannel struct {
	URL     string
	Headers map[string]string
}

func (w *WebhookChannel) Name() string {
	return "webhook"
}

func (w *WebhookChannel) Send(alert *Alert) error {
	payload, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	
	req, err := http.NewRequest("POST", w.URL, strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	
	req.Header.Set("Content-Type", "application/json")
	for key, value := range w.Headers {
		req.Header.Set(key, value)
	}
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log error but don't fail the webhook
			log.Printf("Failed to close response body: %v", err)
		}
	}()
	
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status code %d", resp.StatusCode)
	}
	
	return nil
}

// Console notification channel
type ConsoleChannel struct{}

func (c *ConsoleChannel) Name() string {
	return "console"
}

func (c *ConsoleChannel) Send(alert *Alert) error {
	log.Printf("[ALERT-%s] %s: %s (Source: %s)", alert.Level.String(), alert.Title, alert.Description, alert.Source)
	return nil
}

func NewAlertManager(maxAlerts int) *AlertManager {
	return &AlertManager{
		alerts:    make([]Alert, 0),
		rules:     make(map[string]*AlertRule),
		channels:  make([]NotificationChannel, 0),
		maxAlerts: maxAlerts,
	}
}

func (am *AlertManager) AddRule(rule *AlertRule) {
	am.mutex.Lock()
	defer am.mutex.Unlock()
	am.rules[rule.ID] = rule
}

func (am *AlertManager) RemoveRule(ruleID string) {
	am.mutex.Lock()
	defer am.mutex.Unlock()
	delete(am.rules, ruleID)
}

func (am *AlertManager) AddChannel(channel NotificationChannel) {
	am.mutex.Lock()
	defer am.mutex.Unlock()
	am.channels = append(am.channels, channel)
}

func (am *AlertManager) TriggerAlert(alert *Alert) {
	am.mutex.Lock()
	defer am.mutex.Unlock()
	
	// Add to alert history
	am.alerts = append(am.alerts, *alert)
	
	// Trim alerts if we exceed max
	if len(am.alerts) > am.maxAlerts {
		am.alerts = am.alerts[len(am.alerts)-am.maxAlerts:]
	}
	
	// Send notifications
	go am.sendNotifications(alert)
}

func (am *AlertManager) sendNotifications(alert *Alert) {
	for _, channel := range am.channels {
		if err := channel.Send(alert); err != nil {
			log.Printf("Failed to send alert via %s: %v", channel.Name(), err)
		}
	}
}

func (am *AlertManager) CheckRules(data interface{}) {
	am.mutex.RLock()
	defer am.mutex.RUnlock()
	
	now := time.Now()
	
	for _, rule := range am.rules {
		if !rule.Enabled {
			continue
		}
		
		// Check cooldown
		if now.Sub(rule.LastFired) < rule.Cooldown {
			continue
		}
		
		// Check condition
		if rule.Condition(data) {
			alert := &Alert{
				ID:          fmt.Sprintf("%s-%d", rule.ID, now.Unix()),
				Title:       rule.Name,
				Description: rule.Description,
				Level:       rule.Level,
				Timestamp:   now,
				Source:      "rule-engine",
				Data:        map[string]interface{}{"rule_id": rule.ID},
			}
			
			rule.LastFired = now
			am.TriggerAlert(alert)
		}
	}
}

func (am *AlertManager) GetAlerts(limit int) []Alert {
	am.mutex.RLock()
	defer am.mutex.RUnlock()
	
	if limit <= 0 || limit > len(am.alerts) {
		limit = len(am.alerts)
	}
	
	// Return most recent alerts first
	result := make([]Alert, limit)
	for i := 0; i < limit; i++ {
		result[i] = am.alerts[len(am.alerts)-1-i]
	}
	
	return result
}

func (am *AlertManager) GetRules() map[string]*AlertRule {
	am.mutex.RLock()
	defer am.mutex.RUnlock()
	
	rules := make(map[string]*AlertRule)
	for k, v := range am.rules {
		rules[k] = v
	}
	return rules
}

func (am *AlertManager) ResolveAlert(alertID string) {
	am.mutex.Lock()
	defer am.mutex.Unlock()
	
	for i := range am.alerts {
		if am.alerts[i].ID == alertID {
			am.alerts[i].Resolved = true
			break
		}
	}
}

// Predefined alert rules
func CreateHighTrafficRule(threshold float64) *AlertRule {
	return &AlertRule{
		ID:          "high-traffic",
		Name:        "High Network Traffic",
		Description: fmt.Sprintf("Network traffic exceeded %.2f MB/s", threshold/1024/1024),
		Level:       AlertWarning,
		Enabled:     true,
		Cooldown:    5 * time.Minute,
		Condition: func(data interface{}) bool {
			if stats, ok := data.(map[string]interface{}); ok {
				if byteRate, exists := stats["ByteRate"]; exists {
					if rate, ok := byteRate.(float64); ok {
						return rate > threshold
					}
				}
			}
			return false
		},
	}
}

func CreateSuspiciousConnectionRule() *AlertRule {
	return &AlertRule{
		ID:          "suspicious-connection",
		Name:        "Suspicious Connection Detected",
		Description: "Detected connection to potentially malicious IP",
		Level:       AlertCritical,
		Enabled:     true,
		Cooldown:    1 * time.Minute,
		Condition: func(data interface{}) bool {
			// This would integrate with threat intelligence feeds
			// For now, it's a placeholder
			return false
		},
	}
}

func CreateInterfaceDownRule() *AlertRule {
	return &AlertRule{
		ID:          "interface-down",
		Name:        "Network Interface Down",
		Description: "A monitored network interface has gone down",
		Level:       AlertCritical,
		Enabled:     true,
		Cooldown:    1 * time.Minute,
		Condition: func(data interface{}) bool {
			// This would check interface status
			// For now, it's a placeholder
			return false
		},
	}
}