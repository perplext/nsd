package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/rivo/tview"
	"github.com/perplext/nsd/pkg/netcap"
)

// ConnectionLifetimeVisualization shows how long connections stay alive
type ConnectionLifetimeVisualization struct {
	BaseVisualization
	lifetimes map[string]time.Duration // connection key -> lifetime
}

// NewConnectionLifetimeVisualization creates a new connection lifetime visualization
func NewConnectionLifetimeVisualization() Visualization {
	c := &ConnectionLifetimeVisualization{
		lifetimes: make(map[string]time.Duration),
	}
	c.textView = tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(false)
	c.textView.SetBorder(true).
		SetTitle("Connection Lifetime Chart")
	return c
}

// GetID returns the unique identifier
func (c *ConnectionLifetimeVisualization) GetID() string {
	return "conn_lifetime"
}

// GetName returns the display name
func (c *ConnectionLifetimeVisualization) GetName() string {
	return "Connection Lifetime"
}

// GetDescription returns a description
func (c *ConnectionLifetimeVisualization) GetDescription() string {
	return "Shows how long connections stay alive"
}

// CreateView creates the view
func (c *ConnectionLifetimeVisualization) CreateView() tview.Primitive {
	return c.textView
}

// Update updates the visualization
func (c *ConnectionLifetimeVisualization) Update(monitor *netcap.NetworkMonitor) {
	c.monitor = monitor
	
	// Get connections from all interfaces
	var connections []*netcap.Connection
	for interfaceName := range monitor.GetInterfaceStats() {
		interfaceConns := monitor.GetConnections(interfaceName)
		connections = append(connections, interfaceConns...)
	}
	
	// Calculate lifetimes
	for _, conn := range connections {
		key := fmt.Sprintf("%s:%d-%s:%d", 
			conn.SrcIP, conn.SrcPort, 
			conn.DstIP, conn.DstPort)
		
		// Since FirstSeen is not available, estimate lifetime based on packets and size
		lifetime := time.Duration(conn.Packets) * time.Millisecond * 100 // rough estimate
		c.lifetimes[key] = lifetime
	}
	
	// Categorize lifetimes
	categories := []struct {
		name     string
		min      time.Duration
		max      time.Duration
		count    int
		examples []string
	}{
		{"[0-1s]", 0, 1 * time.Second, 0, []string{}},
		{"[1-10s]", 1 * time.Second, 10 * time.Second, 0, []string{}},
		{"[10-60s]", 10 * time.Second, 60 * time.Second, 0, []string{}},
		{"[1-5m]", 1 * time.Minute, 5 * time.Minute, 0, []string{}},
		{"[5-30m]", 5 * time.Minute, 30 * time.Minute, 0, []string{}},
		{"[30m+]", 30 * time.Minute, 24 * time.Hour * 365, 0, []string{}},
	}
	
	// Count connections in each category
	for _, conn := range connections {
		// Since FirstSeen is not available, estimate lifetime based on packets and size
		lifetime := time.Duration(conn.Packets) * time.Millisecond * 100 // rough estimate
		service := getServiceName(conn)
		
		for i := range categories {
			if lifetime >= categories[i].min && lifetime < categories[i].max {
				categories[i].count++
				if len(categories[i].examples) < 3 {
					categories[i].examples = append(categories[i].examples, service)
				}
				break
			}
		}
	}
	
	// Find max count for scaling
	maxCount := 0
	for _, cat := range categories {
		if cat.count > maxCount {
			maxCount = cat.count
		}
	}
	
	if maxCount == 0 {
		maxCount = 1
	}
	
	// Build visualization
	var output strings.Builder
	
	output.WriteString("[white]Connection Age Distribution\n\n")
	
	// Draw histogram
	barWidth := 40
	totalConns := len(connections)
	
	for _, cat := range categories {
		percentage := 0.0
		if totalConns > 0 {
			percentage = float64(cat.count) / float64(totalConns) * 100
		}
		
		barLen := int(float64(cat.count) / float64(maxCount) * float64(barWidth))
		
		// Create bar
		var bar string
		color := c.getAgeColor(cat.name)
		
		if barLen > 0 {
			// Use different characters based on percentage
			if percentage > 40 {
				bar = strings.Repeat("█", barLen)
			} else if percentage > 20 {
				bar = strings.Repeat("▓", barLen)
			} else if percentage > 10 {
				bar = strings.Repeat("▒", barLen)
			} else {
				bar = strings.Repeat("░", barLen)
			}
		}
		
		// Format line
		output.WriteString(fmt.Sprintf("%-8s %s%s[white]%s %3d (%.1f%%)\n",
			cat.name,
			color,
			bar,
			strings.Repeat(" ", barWidth-len(bar)),
			cat.count,
			percentage))
		
		// Show example services
		if len(cat.examples) > 0 {
			examples := strings.Join(cat.examples, ", ")
			output.WriteString(fmt.Sprintf("         └─ %s\n", examples))
		}
	}
	
	// Statistics
	output.WriteString("\n[white]Connection Statistics:\n")
	output.WriteString(fmt.Sprintf("Total Connections: %d\n", totalConns))
	
	// Calculate average lifetime
	var totalLifetime time.Duration
	for _, lifetime := range c.lifetimes {
		totalLifetime += lifetime
	}
	
	if len(c.lifetimes) > 0 {
		avgLifetime := totalLifetime / time.Duration(len(c.lifetimes))
		output.WriteString(fmt.Sprintf("Average Lifetime: %s\n", c.formatDuration(avgLifetime)))
	}
	
	// Long-lived connections
	output.WriteString("\n[white]Long-lived Connections:\n")
	longLived := c.getLongLivedConnections(connections, 5*time.Minute)
	
	for i, conn := range longLived {
		if i >= 5 {
			break
		}
		
		// Since FirstSeen is not available, estimate lifetime based on packets and size
		lifetime := time.Duration(conn.Packets) * time.Millisecond * 100 // rough estimate
		service := getServiceName(conn)
		
		output.WriteString(fmt.Sprintf("• %s:%d → %s (%s) - %s\n",
			conn.SrcIP, conn.SrcPort,
			service,
			conn.Protocol,
			c.formatDuration(lifetime)))
	}
	
	// Connection type analysis
	output.WriteString("\n[white]By Service Type:\n")
	serviceLifetimes := c.getServiceLifetimes(connections)
	
	for service, stats := range serviceLifetimes {
		avgLifetime := stats.total / time.Duration(stats.count)
		color := c.getServiceColor(service)
		
		bar := strings.Repeat("▪", int(avgLifetime.Minutes())+1)
		if len(bar) > 20 {
			bar = bar[:20] + "..."
		}
		
		output.WriteString(fmt.Sprintf("%s%-10s[white] %s avg: %s\n",
			color,
			service,
			bar,
			c.formatDuration(avgLifetime)))
	}
	
	c.textView.SetText(output.String())
}

type lifetimeStats struct {
	total time.Duration
	count int
}

// getServiceLifetimes calculates average lifetimes by service
func (c *ConnectionLifetimeVisualization) getServiceLifetimes(connections []*netcap.Connection) map[string]*lifetimeStats {
	stats := make(map[string]*lifetimeStats)
	
	for _, conn := range connections {
		service := getServiceName(conn)
		// Since FirstSeen is not available, estimate lifetime based on packets and size
		lifetime := time.Duration(conn.Packets) * time.Millisecond * 100 // rough estimate
		
		if stats[service] == nil {
			stats[service] = &lifetimeStats{}
		}
		
		stats[service].total += lifetime
		stats[service].count++
	}
	
	return stats
}

// getLongLivedConnections returns connections alive longer than threshold
func (c *ConnectionLifetimeVisualization) getLongLivedConnections(connections []*netcap.Connection, threshold time.Duration) []*netcap.Connection {
	var longLived []*netcap.Connection
	
	for _, conn := range connections {
		// Since FirstSeen is not available, estimate lifetime based on packets and size
		lifetime := time.Duration(conn.Packets) * time.Millisecond * 100 // rough estimate
		if lifetime >= threshold {
			longLived = append(longLived, conn)
		}
	}
	
	// Sort by lifetime (longest first)
	for i := 0; i < len(longLived); i++ {
		for j := i + 1; j < len(longLived); j++ {
			// Since FirstSeen is not available, estimate lifetime based on packets and size
			lifetime1 := time.Duration(longLived[i].Packets) * time.Millisecond * 100
			lifetime2 := time.Duration(longLived[j].Packets) * time.Millisecond * 100
			if lifetime2 > lifetime1 {
				longLived[i], longLived[j] = longLived[j], longLived[i]
			}
		}
	}
	
	return longLived
}

// formatDuration formats a duration in human-readable form
func (c *ConnectionLifetimeVisualization) formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	} else if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	} else if d < time.Hour {
		return fmt.Sprintf("%.1fm", d.Minutes())
	} else {
		return fmt.Sprintf("%.1fh", d.Hours())
	}
}

// getAgeColor returns color based on connection age
func (c *ConnectionLifetimeVisualization) getAgeColor(category string) string {
	switch category {
	case "[0-1s]":
		return "[red]"
	case "[1-10s]":
		return "[yellow]"
	case "[10-60s]":
		return "[green]"
	case "[1-5m]":
		return "[cyan]"
	case "[5-30m]":
		return "[blue]"
	case "[30m+]":
		return "[magenta]"
	default:
		return "[white]"
	}
}

// getServiceColor returns color for a service
func (c *ConnectionLifetimeVisualization) getServiceColor(service string) string {
	switch service {
	case "HTTPS", "HTTP":
		return "[green]"
	case "SSH":
		return "[yellow]"
	case "DNS":
		return "[blue]"
	case "Database":
		return "[magenta]"
	default:
		return "[white]"
	}
}

// GetMinSize returns minimum size requirements
func (c *ConnectionLifetimeVisualization) GetMinSize() (width, height int) {
	return 60, 35
}