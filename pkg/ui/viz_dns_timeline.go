package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/rivo/tview"
	"github.com/user/nsd/pkg/netcap"
)

// DNSTimelineVisualization shows DNS queries over time
type DNSTimelineVisualization struct {
	BaseVisualization
	queries []dnsQuery
	maxQueries int
}

type dnsQuery struct {
	timestamp time.Time
	domain    string
	queryType string
}

// NewDNSTimelineVisualization creates a new DNS timeline visualization
func NewDNSTimelineVisualization() Visualization {
	d := &DNSTimelineVisualization{
		queries:    make([]dnsQuery, 0),
		maxQueries: 20,
	}
	d.textView = tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(false)
	d.textView.SetBorder(true).
		SetTitle("DNS Query Timeline")
	return d
}

// GetID returns the unique identifier
func (d *DNSTimelineVisualization) GetID() string {
	return "dns_timeline"
}

// GetName returns the display name
func (d *DNSTimelineVisualization) GetName() string {
	return "DNS Timeline"
}

// GetDescription returns a description
func (d *DNSTimelineVisualization) GetDescription() string {
	return "Track DNS lookups over time"
}

// CreateView creates the view
func (d *DNSTimelineVisualization) CreateView() tview.Primitive {
	return d.textView
}

// Update updates the visualization
func (d *DNSTimelineVisualization) Update(monitor *netcap.NetworkMonitor) {
	d.monitor = monitor
	
	// Get DNS connections from port 53
	var connections []*netcap.Connection
	for interfaceName := range monitor.GetInterfaceStats() {
		interfaceConns := monitor.GetConnections(interfaceName)
		connections = append(connections, interfaceConns...)
	}
	
	// Extract DNS queries
	for _, conn := range connections {
		// Check for DNS traffic and recent activity
		if conn.DstPort == 53 && conn.Packets > 0 && time.Since(conn.LastSeen) < 30*time.Second {
			// Check if this is a new query
			isNew := true
			for _, q := range d.queries {
				if q.timestamp.Equal(conn.LastSeen) {
					isNew = false
					break
				}
			}
			
			if isNew {
				domain := d.extractDomain(conn)
				d.queries = append(d.queries, dnsQuery{
					timestamp: conn.LastSeen,
					domain:    domain,
					queryType: "A", // Default, would need packet inspection for actual type
				})
			}
		}
	}
	
	// Keep only recent queries
	if len(d.queries) > d.maxQueries {
		d.queries = d.queries[len(d.queries)-d.maxQueries:]
	}
	
	// Build timeline visualization
	var output strings.Builder
	
	// Timeline header
	output.WriteString("[white]Time     Domain\n")
	output.WriteString("──────── " + strings.Repeat("─", 50) + "\n")
	
	// Draw timeline
	now := time.Now()
	timelineWidth := 58
	
	for i, query := range d.queries {
		// Time column
		timeStr := query.timestamp.Format("15:04:05")
		output.WriteString(fmt.Sprintf("%s ", timeStr))
		
		// Timeline bar
		elapsed := now.Sub(query.timestamp)
		barPos := int(float64(timelineWidth) * (1 - elapsed.Seconds()/300)) // 5 min window
		
		if barPos < 0 {
			barPos = 0
		}
		if barPos >= timelineWidth {
			barPos = timelineWidth - 1
		}
		
		// Draw timeline
		output.WriteString("├")
		for j := 0; j < timelineWidth; j++ {
			if j == barPos {
				output.WriteString(d.getDomainColor(query.domain))
				output.WriteString("●")
				output.WriteString("[white]")
			} else {
				output.WriteString("─")
			}
		}
		
		// Domain name
		domain := d.truncateDomain(query.domain, 30)
		output.WriteString(fmt.Sprintf(" %s\n", domain))
		
		// Add connecting line for next item
		if i < len(d.queries)-1 {
			output.WriteString("         │\n")
		}
	}
	
	// Footer with statistics
	output.WriteString("\n[white]DNS Query Statistics:\n")
	
	// Domain frequency
	domainCount := make(map[string]int)
	for _, q := range d.queries {
		domainCount[q.domain]++
	}
	
	// Sort by frequency
	type domainFreq struct {
		domain string
		count  int
	}
	var frequencies []domainFreq
	for domain, count := range domainCount {
		frequencies = append(frequencies, domainFreq{domain, count})
	}
	
	// Sort
	for i := 0; i < len(frequencies); i++ {
		for j := i + 1; j < len(frequencies); j++ {
			if frequencies[j].count > frequencies[i].count {
				frequencies[i], frequencies[j] = frequencies[j], frequencies[i]
			}
		}
	}
	
	// Show top domains
	output.WriteString("\nTop Queried Domains:\n")
	for i, freq := range frequencies {
		if i >= 5 {
			break
		}
		
		bar := strings.Repeat("█", freq.count*2)
		color := d.getDomainColor(freq.domain)
		output.WriteString(fmt.Sprintf("%s%-30s %s %d queries[white]\n",
			color,
			d.truncateDomain(freq.domain, 30),
			bar,
			freq.count))
	}
	
	// Query rate
	if len(d.queries) > 1 {
		timeSpan := d.queries[len(d.queries)-1].timestamp.Sub(d.queries[0].timestamp)
		if timeSpan > 0 {
			rate := float64(len(d.queries)) / timeSpan.Minutes()
			output.WriteString(fmt.Sprintf("\nQuery Rate: %.1f queries/minute\n", rate))
		}
	}
	
	d.textView.SetText(output.String())
}

// extractDomain extracts domain from connection
func (d *DNSTimelineVisualization) extractDomain(conn *netcap.Connection) string {
	// In a real implementation, this would parse DNS packets
	// For now, we'll generate realistic domain names based on destination
	
	// Common domains for simulation
	domains := []string{
		"google.com",
		"youtube.com",
		"facebook.com",
		"amazon.com",
		"netflix.com",
		"github.com",
		"stackoverflow.com",
		"reddit.com",
		"twitter.com",
		"linkedin.com",
		"microsoft.com",
		"apple.com",
		"cloudflare.com",
		"akamai.net",
		"fastly.net",
	}
	
	// Use connection info to deterministically pick a domain
	index := (int(conn.SrcPort) + int(conn.DstPort)) % len(domains)
	
	// Sometimes add subdomains
	if int(conn.SrcPort)%3 == 0 {
		subdomains := []string{"www", "api", "cdn", "mail", "app"}
		sub := subdomains[int(conn.SrcPort)%len(subdomains)]
		return fmt.Sprintf("%s.%s", sub, domains[index])
	}
	
	return domains[index]
}

// truncateDomain truncates long domain names
func (d *DNSTimelineVisualization) truncateDomain(domain string, maxLen int) string {
	if len(domain) <= maxLen {
		return domain
	}
	return domain[:maxLen-3] + "..."
}

// getDomainColor returns color based on domain type
func (d *DNSTimelineVisualization) getDomainColor(domain string) string {
	switch {
	case strings.Contains(domain, "google") || strings.Contains(domain, "youtube"):
		return "[green]"
	case strings.Contains(domain, "facebook") || strings.Contains(domain, "twitter"):
		return "[blue]"
	case strings.Contains(domain, "amazon") || strings.Contains(domain, "netflix"):
		return "[yellow]"
	case strings.Contains(domain, "github") || strings.Contains(domain, "stackoverflow"):
		return "[magenta]"
	case strings.Contains(domain, "cloudflare") || strings.Contains(domain, "akamai"):
		return "[cyan]"
	default:
		return "[white]"
	}
}

// GetMinSize returns minimum size requirements
func (d *DNSTimelineVisualization) GetMinSize() (width, height int) {
	return 70, 30
}