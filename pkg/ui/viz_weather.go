package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/rivo/tview"
	"github.com/perplext/nsd/pkg/netcap"
	"github.com/shirou/gopsutil/v3/cpu"
)

// WeatherMapVisualization shows network conditions as weather
type WeatherMapVisualization struct {
	BaseVisualization
	lastCPU      float64
	lastBandwidth float64
}

// NewWeatherMapVisualization creates a new weather map visualization
func NewWeatherMapVisualization() Visualization {
	w := &WeatherMapVisualization{}
	w.textView = tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(false)
	w.textView.SetBorder(true).
		SetTitle("Network Weather Map")
	return w
}

// GetID returns the unique identifier
func (w *WeatherMapVisualization) GetID() string {
	return "weather"
}

// GetName returns the display name
func (w *WeatherMapVisualization) GetName() string {
	return "Network Weather"
}

// GetDescription returns a description
func (w *WeatherMapVisualization) GetDescription() string {
	return "Network conditions visualization as weather"
}

// CreateView creates the view
func (w *WeatherMapVisualization) CreateView() tview.Primitive {
	return w.textView
}

// Update updates the visualization
func (w *WeatherMapVisualization) Update(monitor *netcap.NetworkMonitor) {
	w.monitor = monitor
	
	// Get network stats
	var connections []*netcap.Connection
	for interfaceName := range monitor.Interfaces {
		connections = append(connections, monitor.GetConnections(interfaceName)...)
	}
	activeConns := 0
	totalBandwidth := uint64(0)
	protocols := make(map[string]int)
	
	for _, conn := range connections {
		if time.Since(conn.LastSeen) < 30*time.Second && conn.Packets > 0 {
			activeConns++
			totalBandwidth += conn.Size
			protocols[conn.Protocol]++
		}
	}
	
	// Get CPU usage
	cpuPercent, _ := cpu.Percent(100*time.Millisecond, false)
	cpuUsage := 0.0
	if len(cpuPercent) > 0 {
		cpuUsage = cpuPercent[0]
	}
	
	// Calculate weather conditions
	weather, emoji := w.calculateWeather(activeConns, totalBandwidth, cpuUsage)
	
	// Build visualization
	var output strings.Builder
	
	// Weather header
	output.WriteString("┌─────────────────────────────────┐\n")
	output.WriteString(fmt.Sprintf("│ Network Weather: %s  %-11s│\n", emoji, weather))
	output.WriteString(fmt.Sprintf("├─────────────────────────────────┤\n"))
	
	// Traffic visualization
	output.WriteString("│ ")
	trafficLevel := w.getTrafficLevel(totalBandwidth)
	for i := 0; i < 31; i++ {
		if i < trafficLevel {
			if i < 10 {
				output.WriteString("[green]░[white]")
			} else if i < 20 {
				output.WriteString("[yellow]▒[white]")
			} else {
				output.WriteString("[red]▓[white]")
			}
		} else {
			output.WriteString(" ")
		}
	}
	output.WriteString(" │\n")
	
	// Conditions
	conditions := w.getConditions(activeConns, totalBandwidth, cpuUsage)
	for _, condition := range conditions {
		output.WriteString(fmt.Sprintf("│ %s%-31s%s│\n", condition.icon, condition.text, strings.Repeat(" ", 31-len(condition.text))))
	}
	
	output.WriteString("│                                 │\n")
	
	// Metrics
	output.WriteString(fmt.Sprintf("│ 🌡️  CPU: %3.0f%% | Bandwidth: %3.0f%% │\n", 
		cpuUsage, float64(totalBandwidth)/1024/1024))
	
	output.WriteString("└─────────────────────────────────┘\n")
	
	// Forecast
	output.WriteString("\n[white]Network Forecast:\n")
	forecast := w.generateForecast(activeConns, totalBandwidth, cpuUsage)
	for _, line := range forecast {
		output.WriteString(fmt.Sprintf("• %s\n", line))
	}
	
	// Protocol breakdown
	output.WriteString("\n[white]Active Protocols:\n")
	for proto, count := range protocols {
		bar := strings.Repeat("█", count/2+1)
		output.WriteString(fmt.Sprintf("%-6s %s %d\n", proto, bar, count))
	}
	
	w.textView.SetText(output.String())
	
	// Store for trend analysis
	w.lastCPU = cpuUsage
	w.lastBandwidth = float64(totalBandwidth)
}

// calculateWeather determines weather conditions
func (w *WeatherMapVisualization) calculateWeather(conns int, bandwidth uint64, cpu float64) (string, string) {
	score := 0
	
	// Connection score
	if conns < 50 {
		score += 3
	} else if conns < 100 {
		score += 2
	} else if conns < 200 {
		score += 1
	}
	
	// Bandwidth score (MB/s)
	bwMBps := float64(bandwidth) / 1024 / 1024
	if bwMBps < 10 {
		score += 3
	} else if bwMBps < 50 {
		score += 2
	} else if bwMBps < 100 {
		score += 1
	}
	
	// CPU score
	if cpu < 30 {
		score += 3
	} else if cpu < 60 {
		score += 2
	} else if cpu < 80 {
		score += 1
	}
	
	// Determine weather
	switch {
	case score >= 8:
		return "SUNNY", "☀️"
	case score >= 6:
		return "PARTLY CLOUDY", "⛅"
	case score >= 4:
		return "CLOUDY", "☁️"
	case score >= 2:
		return "RAINY", "🌧️"
	default:
		return "STORMY", "⛈️"
	}
}

// getTrafficLevel returns traffic level (0-31)
func (w *WeatherMapVisualization) getTrafficLevel(bandwidth uint64) int {
	mbps := float64(bandwidth) / 1024 / 1024
	if mbps > 100 {
		return 31
	}
	return int(mbps * 31 / 100)
}

type condition struct {
	icon string
	text string
}

// getConditions returns current network conditions
func (w *WeatherMapVisualization) getConditions(conns int, bandwidth uint64, cpu float64) []condition {
	conditions := []condition{}
	
	// Connection status
	if conns > 200 {
		conditions = append(conditions, condition{"⚡", "High connection count"})
	} else if conns > 100 {
		conditions = append(conditions, condition{"⚡", "Moderate connections"})
	} else {
		conditions = append(conditions, condition{"✓ ", "Normal connection count"})
	}
	
	// Bandwidth status
	bwMBps := float64(bandwidth) / 1024 / 1024
	if bwMBps > 80 {
		conditions = append(conditions, condition{"⚡", "Heavy network traffic"})
	} else if bwMBps > 40 {
		conditions = append(conditions, condition{"⚡", "Moderate traffic"})
	} else {
		conditions = append(conditions, condition{"✓ ", "Light traffic"})
	}
	
	// CPU status
	if cpu > 80 {
		conditions = append(conditions, condition{"🔥", "High CPU usage detected"})
	}
	
	// Trends
	if w.lastBandwidth > 0 {
		change := (float64(bandwidth) - w.lastBandwidth) / w.lastBandwidth * 100
		if change > 50 {
			conditions = append(conditions, condition{"📈", "Traffic surge detected"})
		} else if change < -50 {
			conditions = append(conditions, condition{"📉", "Traffic drop detected"})
		}
	}
	
	return conditions
}

// generateForecast generates network forecast
func (w *WeatherMapVisualization) generateForecast(conns int, bandwidth uint64, cpu float64) []string {
	forecast := []string{}
	
	// Time-based predictions
	hour := time.Now().Hour()
	if hour >= 9 && hour <= 17 {
		forecast = append(forecast, "Business hours: Expect continued activity")
	} else if hour >= 18 && hour <= 23 {
		forecast = append(forecast, "Evening hours: Streaming traffic likely")
	} else {
		forecast = append(forecast, "Off-peak hours: Lower traffic expected")
	}
	
	// Trend-based predictions
	if conns > 150 {
		forecast = append(forecast, "High connection count may impact latency")
	}
	
	if cpu > 70 {
		forecast = append(forecast, "CPU usage elevated - monitor for bottlenecks")
	}
	
	bwMBps := float64(bandwidth) / 1024 / 1024
	if bwMBps > 50 {
		forecast = append(forecast, "Consider bandwidth optimization")
	}
	
	return forecast
}

// GetMinSize returns minimum size requirements
func (w *WeatherMapVisualization) GetMinSize() (width, height int) {
	return 40, 25
}