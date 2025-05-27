package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rivo/tview"
	"github.com/user/nsd/pkg/netcap"
	"github.com/user/nsd/pkg/security"
)

// DetectionDashboardVisualization shows real-time security detections
type DetectionDashboardVisualization struct {
	BaseVisualization
	detectionEngine *security.UnifiedDetectionEngine
	alerts          []security.UnifiedAlert
	alertStats      map[string]*AlertStatistics
	ipStats         map[string]*IPStatistics
	signatureStats  map[string]*SignatureStatistics
	maxAlerts       int
	refreshRate     time.Duration
	lastUpdate      time.Time
}

type AlertStatistics struct {
	Count        int
	FirstSeen    time.Time
	LastSeen     time.Time
	Severity     string
	Engines      map[string]int
}

type IPStatistics struct {
	IP           string
	AlertCount   int
	AsSource     int
	AsDestination int
	FirstSeen    time.Time
	LastSeen     time.Time
	TopSignatures []string
	Reputation   string
}

type SignatureStatistics struct {
	Name         string
	Count        int
	Severity     string
	Category     string
	FirstSeen    time.Time
	LastSeen     time.Time
	SourceIPs    map[string]int
	DestinationIPs map[string]int
}

// NewDetectionDashboardVisualization creates a new detection dashboard
func NewDetectionDashboardVisualization() Visualization {
	config := security.UnifiedConfig{
		EnabledEngines: []string{"snort", "suricata", "zeek", "yara", "sigma"},
		TimeWindow:     5 * time.Minute,
		OutputFormat:   "json",
	}
	
	d := &DetectionDashboardVisualization{
		detectionEngine: security.NewUnifiedDetectionEngine(config),
		alerts:          make([]security.UnifiedAlert, 0),
		alertStats:      make(map[string]*AlertStatistics),
		ipStats:         make(map[string]*IPStatistics),
		signatureStats:  make(map[string]*SignatureStatistics),
		maxAlerts:       1000,
		refreshRate:     1 * time.Second,
	}
	
	d.textView = tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(false)
	d.textView.SetBorder(true).
		SetTitle("🛡️ Real-Time Detection Dashboard")
	
	return d
}


// GetID returns the unique identifier
func (d *DetectionDashboardVisualization) GetID() string {
	return "detection_dashboard"
}

// GetName returns the display name
func (d *DetectionDashboardVisualization) GetName() string {
	return "Detection Dashboard"
}

// GetDescription returns a description
func (d *DetectionDashboardVisualization) GetDescription() string {
	return "Real-time security detection dashboard with unified threat alerts"
}

// CreateView creates the view
func (d *DetectionDashboardVisualization) CreateView() tview.Primitive {
	return d.textView
}

// Update updates the visualization
func (d *DetectionDashboardVisualization) Update(monitor *netcap.NetworkMonitor) {
	d.monitor = monitor
	
	// Get alerts from detection engine
	newAlerts := d.detectionEngine.GetAlerts()
	
	// Filter new alerts since last update
	var recentAlerts []security.UnifiedAlert
	for _, alert := range newAlerts {
		if alert.Timestamp.After(d.lastUpdate) {
			recentAlerts = append(recentAlerts, alert)
		}
	}
	
	// Add new alerts
	d.alerts = append(d.alerts, recentAlerts...)
	
	// Keep only recent alerts
	if len(d.alerts) > d.maxAlerts {
		d.alerts = d.alerts[len(d.alerts)-d.maxAlerts:]
	}
	
	// Update statistics
	d.updateStatistics()
	
	// Update display
	if time.Since(d.lastUpdate) >= d.refreshRate {
		d.updateDisplay()
		d.lastUpdate = time.Now()
	}
}


func (d *DetectionDashboardVisualization) updateStatistics() {
	// Clear old stats
	d.alertStats = make(map[string]*AlertStatistics)
	d.ipStats = make(map[string]*IPStatistics)
	d.signatureStats = make(map[string]*SignatureStatistics)
	
	// Process all alerts
	for _, alert := range d.alerts {
		// Update alert statistics
		key := fmt.Sprintf("%s:%s", alert.Signature, alert.Severity)
		if stats, exists := d.alertStats[key]; exists {
			stats.Count++
			stats.LastSeen = alert.Timestamp
			stats.Engines[alert.Engine]++
		} else {
			d.alertStats[key] = &AlertStatistics{
				Count:     1,
				FirstSeen: alert.Timestamp,
				LastSeen:  alert.Timestamp,
				Severity:  string(alert.Severity),
				Engines:   map[string]int{alert.Engine: 1},
			}
		}
		
		// Update IP statistics
		d.updateIPStats(alert.SourceIP, alert, true)
		d.updateIPStats(alert.DestIP, alert, false)
		
		// Update signature statistics
		if sigStats, exists := d.signatureStats[alert.Signature]; exists {
			sigStats.Count++
			sigStats.LastSeen = alert.Timestamp
			sigStats.SourceIPs[alert.SourceIP]++
			sigStats.DestinationIPs[alert.DestIP]++
		} else {
			d.signatureStats[alert.Signature] = &SignatureStatistics{
				Name:           alert.Signature,
				Count:          1,
				Severity:       string(alert.Severity),
				Category:       alert.Type,
				FirstSeen:      alert.Timestamp,
				LastSeen:       alert.Timestamp,
				SourceIPs:      map[string]int{alert.SourceIP: 1},
				DestinationIPs: map[string]int{alert.DestIP: 1},
			}
		}
	}
}

func (d *DetectionDashboardVisualization) updateIPStats(ip string, alert security.UnifiedAlert, asSource bool) {
	if ip == "" {
		return
	}
	
	stats, exists := d.ipStats[ip]
	if !exists {
		stats = &IPStatistics{
			IP:            ip,
			FirstSeen:     alert.Timestamp,
			TopSignatures: make([]string, 0),
			Reputation:    d.getIPReputation(ip),
		}
		d.ipStats[ip] = stats
	}
	
	stats.AlertCount++
	stats.LastSeen = alert.Timestamp
	
	if asSource {
		stats.AsSource++
	} else {
		stats.AsDestination++
	}
	
	// Update top signatures
	found := false
	for _, sig := range stats.TopSignatures {
		if sig == alert.Signature {
			found = true
			break
		}
	}
	if !found && len(stats.TopSignatures) < 5 {
		stats.TopSignatures = append(stats.TopSignatures, alert.Signature)
	}
}

func (d *DetectionDashboardVisualization) getIPReputation(ip string) string {
	// Simplified reputation check
	if strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") {
		return "Internal"
	}
	// In real implementation, would check threat intelligence
	return "Unknown"
}

func (d *DetectionDashboardVisualization) updateDisplay() {
	var output strings.Builder
	
	// Header with timestamp
	output.WriteString(fmt.Sprintf("[white]🛡️  Security Detection Dashboard - Last Update: %s\n\n",
		time.Now().Format("15:04:05")))
	
	// Summary statistics
	output.WriteString(d.renderSummary())
	
	// Real-time alerts table
	output.WriteString("\n[yellow]═══ Real-Time Alerts ═══[white]\n")
	output.WriteString(d.renderAlertsTable())
	
	// Top attacked IPs
	output.WriteString("\n[yellow]═══ Top Targeted IPs ═══[white]\n")
	output.WriteString(d.renderTopIPs())
	
	// Top signatures
	output.WriteString("\n[yellow]═══ Top Signatures ═══[white]\n")
	output.WriteString(d.renderTopSignatures())
	
	// Threat timeline
	output.WriteString("\n[yellow]═══ Threat Timeline ═══[white]\n")
	output.WriteString(d.renderThreatTimeline())
	
	d.textView.SetText(output.String())
}

func (d *DetectionDashboardVisualization) renderSummary() string {
	var output strings.Builder
	
	totalAlerts := len(d.alerts)
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0
	
	for _, alert := range d.alerts {
		switch alert.Severity {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		case "medium":
			mediumCount++
		case "low":
			lowCount++
		}
	}
	
	output.WriteString("[white]📊 Alert Summary:\n")
	output.WriteString(fmt.Sprintf("   Total Alerts: [yellow]%d[white]\n", totalAlerts))
	output.WriteString(fmt.Sprintf("   [red]Critical: %d[white]  [orange]High: %d[white]  [yellow]Medium: %d[white]  [green]Low: %d[white]\n",
		criticalCount, highCount, mediumCount, lowCount))
	
	// Alert rate
	if totalAlerts > 0 {
		timeRange := d.alerts[len(d.alerts)-1].Timestamp.Sub(d.alerts[0].Timestamp)
		if timeRange > 0 {
			alertRate := float64(totalAlerts) / timeRange.Minutes()
			output.WriteString(fmt.Sprintf("   Alert Rate: [cyan]%.1f alerts/min[white]\n", alertRate))
		}
	}
	
	return output.String()
}

func (d *DetectionDashboardVisualization) renderAlertsTable() string {
	var output strings.Builder
	
	// Table header
	output.WriteString("[gray]Time      │ Severity │ Source IP       │ Dest IP         │ Signature                     │ Engine  │ Category[white]\n")
	output.WriteString("[gray]──────────┼──────────┼─────────────────┼─────────────────┼───────────────────────────────┼─────────┼──────────[white]\n")
	
	// Show last 15 alerts
	start := len(d.alerts) - 15
	if start < 0 {
		start = 0
	}
	
	for i := len(d.alerts) - 1; i >= start; i-- {
		alert := d.alerts[i]
		
		// Color based on severity
		severityColor := d.getSeverityColor(string(alert.Severity))
		
		// Truncate signature if too long
		signature := alert.Signature
		if len(signature) > 30 {
			signature = signature[:27] + "..."
		}
		
		// Format IPs
		srcIP := d.formatIP(alert.SourceIP)
		dstIP := d.formatIP(alert.DestIP)
		
		output.WriteString(fmt.Sprintf("%s │ %s%-8s[white] │ %-15s │ %-15s │ %-29s │ %-7s │ %s\n",
			alert.Timestamp.Format("15:04:05"),
			severityColor,
			alert.Severity,
			srcIP,
			dstIP,
			signature,
			alert.Engine,
			alert.Type))
	}
	
	if len(d.alerts) > 15 {
		output.WriteString(fmt.Sprintf("\n[gray]... and %d more alerts[white]\n", len(d.alerts)-15))
	}
	
	return output.String()
}

func (d *DetectionDashboardVisualization) renderTopIPs() string {
	var output strings.Builder
	
	// Sort IPs by alert count
	type ipStat struct {
		ip    string
		stats *IPStatistics
	}
	
	var ipList []ipStat
	for ip, stats := range d.ipStats {
		ipList = append(ipList, ipStat{ip, stats})
	}
	
	sort.Slice(ipList, func(i, j int) bool {
		return ipList[i].stats.AlertCount > ipList[j].stats.AlertCount
	})
	
	// Show top 10
	maxShow := 10
	if len(ipList) < maxShow {
		maxShow = len(ipList)
	}
	
	for i := 0; i < maxShow; i++ {
		ip := ipList[i]
		repColor := "[white]"
		if ip.stats.Reputation == "Internal" {
			repColor = "[green]"
		} else if ip.stats.Reputation == "Malicious" {
			repColor = "[red]"
		}
		
		// Create alert bar
		barLength := ip.stats.AlertCount / 5
		if barLength > 20 {
			barLength = 20
		}
		bar := strings.Repeat("█", barLength)
		
		output.WriteString(fmt.Sprintf("%-15s %s│[white] %s[red]%s[white] Alerts: %d (Src: %d, Dst: %d) %s%s[white]\n",
			ip.ip,
			repColor,
			repColor,
			bar,
			ip.stats.AlertCount,
			ip.stats.AsSource,
			ip.stats.AsDestination,
			repColor,
			ip.stats.Reputation))
		
		// Show top signatures for this IP
		if len(ip.stats.TopSignatures) > 0 {
			output.WriteString(fmt.Sprintf("                └─ Top: %s\n", 
				strings.Join(ip.stats.TopSignatures[:min(3, len(ip.stats.TopSignatures))], ", ")))
		}
	}
	
	return output.String()
}

func (d *DetectionDashboardVisualization) renderTopSignatures() string {
	var output strings.Builder
	
	// Sort signatures by count
	type sigStat struct {
		name  string
		stats *SignatureStatistics
	}
	
	var sigList []sigStat
	for name, stats := range d.signatureStats {
		sigList = append(sigList, sigStat{name, stats})
	}
	
	sort.Slice(sigList, func(i, j int) bool {
		return sigList[i].stats.Count > sigList[j].stats.Count
	})
	
	// Show top 10
	maxShow := 10
	if len(sigList) < maxShow {
		maxShow = len(sigList)
	}
	
	for i := 0; i < maxShow; i++ {
		sig := sigList[i]
		severityColor := d.getSeverityColor(sig.stats.Severity)
		
		// Truncate name if needed
		name := sig.name
		if len(name) > 40 {
			name = name[:37] + "..."
		}
		
		output.WriteString(fmt.Sprintf("%-40s %s%-8s[white] Count: %-4d Category: %-15s\n",
			name,
			severityColor,
			sig.stats.Severity,
			sig.stats.Count,
			sig.stats.Category))
		
		// Show unique source/dest counts
		output.WriteString(fmt.Sprintf("   └─ Unique Sources: %d, Unique Destinations: %d\n",
			len(sig.stats.SourceIPs), len(sig.stats.DestinationIPs)))
	}
	
	return output.String()
}

func (d *DetectionDashboardVisualization) renderThreatTimeline() string {
	var output strings.Builder
	
	// Create timeline buckets (last 60 minutes, 5-minute buckets)
	now := time.Now()
	buckets := make(map[int]int)
	severityBuckets := make(map[int]map[string]int)
	
	for _, alert := range d.alerts {
		minutesAgo := int(now.Sub(alert.Timestamp).Minutes())
		bucket := minutesAgo / 5
		
		if bucket < 12 { // Last hour
			buckets[bucket]++
			if severityBuckets[bucket] == nil {
				severityBuckets[bucket] = make(map[string]int)
			}
			severityBuckets[bucket][string(alert.Severity)]++
		}
	}
	
	// Find max for scaling
	maxCount := 0
	for _, count := range buckets {
		if count > maxCount {
			maxCount = count
		}
	}
	
	if maxCount == 0 {
		output.WriteString("[gray]No alerts in the last hour[white]\n")
		return output.String()
	}
	
	// Draw timeline
	output.WriteString("[gray]60m ──────────────────────────────────────────────────────────── Now[white]\n")
	
	// Draw bars
	for i := 11; i >= 0; i-- {
		count := buckets[i]
		if count == 0 {
			output.WriteString("     ")
		} else {
			height := (count * 4) / maxCount
			if height == 0 {
				height = 1
			}
			
			// Get dominant severity
			sevCounts := severityBuckets[i]
			dominantSev := "low"
			maxSevCount := 0
			for sev, cnt := range sevCounts {
				if cnt > maxSevCount {
					maxSevCount = cnt
					dominantSev = sev
				}
			}
			
			color := d.getSeverityColor(dominantSev)
			bar := strings.Repeat("▄", height)
			output.WriteString(fmt.Sprintf("%s%-4s[white] ", color, bar))
		}
	}
	output.WriteString("\n")
	
	// Time labels
	output.WriteString("[gray]")
	for i := 11; i >= 0; i-- {
		output.WriteString(fmt.Sprintf("%-5d", i*5))
	}
	output.WriteString(" (minutes ago)[white]\n")
	
	return output.String()
}

func (d *DetectionDashboardVisualization) getSeverityColor(severity string) string {
	switch severity {
	case "critical":
		return "[red]"
	case "high":
		return "[orange]"
	case "medium":
		return "[yellow]"
	case "low":
		return "[green]"
	default:
		return "[white]"
	}
}

func (d *DetectionDashboardVisualization) formatIP(ip string) string {
	if ip == "" {
		return "N/A"
	}
	return ip
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetMinSize returns minimum size requirements
func (d *DetectionDashboardVisualization) GetMinSize() (width, height int) {
	return 120, 50
}

// SupportsFullscreen indicates this visualization works well in fullscreen
func (d *DetectionDashboardVisualization) SupportsFullscreen() bool {
	return true
}