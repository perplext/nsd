package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/rivo/tview"
	"github.com/user/nsd/pkg/netcap"
)

// HeatmapVisualization shows traffic patterns over time
type HeatmapVisualization struct {
	BaseVisualization
	trafficData [7][24]float64 // 7 days x 24 hours
	currentDay  int
	currentHour int
}

// NewHeatmapVisualization creates a new heatmap visualization
func NewHeatmapVisualization() Visualization {
	h := &HeatmapVisualization{}
	h.textView = tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(false)
	h.textView.SetBorder(true).
		SetTitle("Traffic Heatmap Calendar")
	
	// Initialize with some sample data
	now := time.Now()
	h.currentDay = int(now.Weekday())
	h.currentHour = now.Hour()
	
	return h
}

// GetID returns the unique identifier
func (h *HeatmapVisualization) GetID() string {
	return "heatmap"
}

// GetName returns the display name
func (h *HeatmapVisualization) GetName() string {
	return "Traffic Heatmap"
}

// GetDescription returns a description
func (h *HeatmapVisualization) GetDescription() string {
	return "Shows traffic patterns over hours and days"
}

// CreateView creates the view
func (h *HeatmapVisualization) CreateView() tview.Primitive {
	return h.textView
}

// Update updates the visualization
func (h *HeatmapVisualization) Update(monitor *netcap.NetworkMonitor) {
	h.monitor = monitor
	
	// Get current traffic
	var connections []*netcap.Connection
	for interfaceName := range monitor.GetInterfaceStats() {
		interfaceConns := monitor.GetConnections(interfaceName)
		connections = append(connections, interfaceConns...)
	}
	var currentTraffic float64
	
	for _, conn := range connections {
		if time.Since(conn.LastSeen) < 5*time.Minute {
			currentTraffic += float64(conn.Size)
		}
	}
	
	// Update current hour's data
	now := time.Now()
	h.currentDay = int(now.Weekday())
	h.currentHour = now.Hour()
	
	// Rolling average to smooth the data
	oldValue := h.trafficData[h.currentDay][h.currentHour]
	h.trafficData[h.currentDay][h.currentHour] = (oldValue*0.7 + currentTraffic*0.3)
	
	// Find max traffic for normalization
	maxTraffic := 0.0
	for day := 0; day < 7; day++ {
		for hour := 0; hour < 24; hour++ {
			if h.trafficData[day][hour] > maxTraffic {
				maxTraffic = h.trafficData[day][hour]
			}
		}
	}
	
	// Build the heatmap
	var output strings.Builder
	
	// Header
	output.WriteString("Hour  ")
	for hour := 0; hour < 24; hour += 2 {
		output.WriteString(fmt.Sprintf("%02d ", hour))
	}
	output.WriteString("\n")
	
	// Days
	days := []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}
	for day := 0; day < 7; day++ {
		output.WriteString(fmt.Sprintf("%-5s ", days[day]))
		
		for hour := 0; hour < 24; hour++ {
			intensity := 0.0
			if maxTraffic > 0 {
				intensity = h.trafficData[day][hour] / maxTraffic
			}
			
			// Current cell indicator
			if day == h.currentDay && hour == h.currentHour {
				output.WriteString("[yellow]")
			}
			
			// Heat character based on intensity
			if intensity > 0.75 {
				output.WriteString("██")
			} else if intensity > 0.5 {
				output.WriteString("▓▓")
			} else if intensity > 0.25 {
				output.WriteString("▒▒")
			} else if intensity > 0 {
				output.WriteString("░░")
			} else {
				output.WriteString("  ")
			}
			
			if day == h.currentDay && hour == h.currentHour {
				output.WriteString("[white]")
			}
			
			output.WriteString(" ")
		}
		output.WriteString("\n")
	}
	
	// Legend
	output.WriteString("\n[white]Legend: ")
	output.WriteString("░░ Light  ")
	output.WriteString("▒▒ Moderate  ")
	output.WriteString("▓▓ Heavy  ")
	output.WriteString("██ Peak  ")
	output.WriteString("[yellow]██[white] Current\n")
	
	// Traffic summary
	output.WriteString(fmt.Sprintf("\nCurrent Traffic: %.2f MB/s", currentTraffic/1024/1024))
	
	// Pattern analysis
	patterns := h.analyzePatterns()
	output.WriteString("\n\nTraffic Patterns:\n")
	for _, pattern := range patterns {
		output.WriteString(fmt.Sprintf("• %s\n", pattern))
	}
	
	h.textView.SetText(output.String())
}

// analyzePatterns identifies traffic patterns
func (h *HeatmapVisualization) analyzePatterns() []string {
	patterns := []string{}
	
	// Find peak hours
	peakHour := 0
	peakTraffic := 0.0
	for hour := 0; hour < 24; hour++ {
		hourTotal := 0.0
		for day := 0; day < 7; day++ {
			hourTotal += h.trafficData[day][hour]
		}
		if hourTotal > peakTraffic {
			peakTraffic = hourTotal
			peakHour = hour
		}
	}
	
	if peakTraffic > 0 {
		patterns = append(patterns, fmt.Sprintf("Peak traffic typically at %02d:00", peakHour))
	}
	
	// Weekend vs weekday
	weekdayTotal := 0.0
	weekendTotal := 0.0
	for day := 1; day <= 5; day++ {
		for hour := 0; hour < 24; hour++ {
			weekdayTotal += h.trafficData[day][hour]
		}
	}
	for _, day := range []int{0, 6} {
		for hour := 0; hour < 24; hour++ {
			weekendTotal += h.trafficData[day][hour]
		}
	}
	
	if weekdayTotal > weekendTotal*2 {
		patterns = append(patterns, "Higher traffic on weekdays")
	} else if weekendTotal > weekdayTotal*2 {
		patterns = append(patterns, "Higher traffic on weekends")
	} else {
		patterns = append(patterns, "Consistent traffic throughout the week")
	}
	
	// Business hours analysis
	businessHoursTraffic := 0.0
	afterHoursTraffic := 0.0
	for day := 1; day <= 5; day++ { // Weekdays only
		for hour := 9; hour < 17; hour++ {
			businessHoursTraffic += h.trafficData[day][hour]
		}
		for hour := 0; hour < 9; hour++ {
			afterHoursTraffic += h.trafficData[day][hour]
		}
		for hour := 17; hour < 24; hour++ {
			afterHoursTraffic += h.trafficData[day][hour]
		}
	}
	
	if businessHoursTraffic > afterHoursTraffic*1.5 {
		patterns = append(patterns, "Business hours show increased activity")
	}
	
	return patterns
}

// GetMinSize returns minimum size requirements
func (h *HeatmapVisualization) GetMinSize() (width, height int) {
	return 80, 20
}