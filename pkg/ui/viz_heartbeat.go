package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/rivo/tview"
	"github.com/perplext/nsd/pkg/netcap"
)

// HeartbeatVisualization shows network health as EKG-style graphs
type HeartbeatVisualization struct {
	BaseVisualization
	latencyHistory []float64
	packetHistory  []float64
	lossHistory    []float64
	maxHistory     int
}

// NewHeartbeatVisualization creates a new heartbeat visualization
func NewHeartbeatVisualization() Visualization {
	h := &HeartbeatVisualization{
		maxHistory:     60,
		latencyHistory: make([]float64, 0, 60),
		packetHistory:  make([]float64, 0, 60),
		lossHistory:    make([]float64, 0, 60),
	}
	h.textView = tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(false)
	h.textView.SetBorder(true).
		SetTitle("Network Heartbeat Monitor")
	return h
}

// GetID returns the unique identifier
func (h *HeartbeatVisualization) GetID() string {
	return "heartbeat"
}

// GetName returns the display name
func (h *HeartbeatVisualization) GetName() string {
	return "Network Heartbeat"
}

// GetDescription returns a description
func (h *HeartbeatVisualization) GetDescription() string {
	return "EKG-style visualization of network health"
}

// CreateView creates the view
func (h *HeartbeatVisualization) CreateView() tview.Primitive {
	return h.textView
}

// Update updates the visualization
func (h *HeartbeatVisualization) Update(monitor *netcap.NetworkMonitor) {
	h.monitor = monitor
	
	// Simulate network metrics (in real implementation, these would come from actual measurements)
	// For now, we'll calculate from connection data
	var connections []*netcap.Connection
	for interfaceName := range monitor.GetInterfaceStats() {
		interfaceConns := monitor.GetConnections(interfaceName)
		connections = append(connections, interfaceConns...)
	}
	
	// Calculate average latency (simulated)
	var avgLatency float64 = 20.0 // Base latency
	activeConns := 0
	var totalPackets uint64
	
	for _, conn := range connections {
		if time.Since(conn.LastSeen) < 5*time.Second {
			activeConns++
			totalPackets += conn.Packets
		}
	}
	
	// Simulate latency based on active connections
	if activeConns > 0 {
		avgLatency += float64(activeConns) * 2
	}
	
	// Add some variation
	variation := float64(time.Now().UnixNano()%10) - 5
	avgLatency += variation
	
	// Update histories
	h.latencyHistory = append(h.latencyHistory, avgLatency)
	h.packetHistory = append(h.packetHistory, float64(totalPackets))
	h.lossHistory = append(h.lossHistory, float64(activeConns%3)) // Simulated loss
	
	// Trim histories
	if len(h.latencyHistory) > h.maxHistory {
		h.latencyHistory = h.latencyHistory[len(h.latencyHistory)-h.maxHistory:]
	}
	if len(h.packetHistory) > h.maxHistory {
		h.packetHistory = h.packetHistory[len(h.packetHistory)-h.maxHistory:]
	}
	if len(h.lossHistory) > h.maxHistory {
		h.lossHistory = h.lossHistory[len(h.lossHistory)-h.maxHistory:]
	}
	
	// Draw the heartbeat graphs
	var output strings.Builder
	
	// Latency graph
	output.WriteString("[yellow]Latency (ms)[white]\n")
	h.drawHeartbeat(&output, h.latencyHistory, 5, '┌', '┐', '└', '┘', '─')
	output.WriteString("\n\n")
	
	// Packet rate graph
	output.WriteString("[green]Packet Rate[white]\n")
	h.drawPulse(&output, h.packetHistory, 5, '╱', '╲')
	output.WriteString("\n\n")
	
	// Packet loss indicators
	output.WriteString("[red]Packet Loss[white]\n")
	h.drawLossIndicators(&output, h.lossHistory)
	output.WriteString("\n\n")
	
	// Health summary
	health := h.calculateHealth(avgLatency, float64(totalPackets), h.lossHistory)
	output.WriteString(fmt.Sprintf("Network Health: %s\n", health))
	output.WriteString(fmt.Sprintf("Active Connections: %d | Avg Latency: %.1fms | Total Packets: %d",
		activeConns, avgLatency, totalPackets))
	
	h.textView.SetText(output.String())
}

// drawHeartbeat draws an EKG-style heartbeat line
func (h *HeartbeatVisualization) drawHeartbeat(output *strings.Builder, data []float64, height int, upChar, downChar, bottomUp, bottomDown, flatChar rune) {
	if len(data) == 0 {
		return
	}
	
	// Normalize data
	maxVal := 0.0
	for _, v := range data {
		if v > maxVal {
			maxVal = v
		}
	}
	if maxVal == 0 {
		maxVal = 1
	}
	
	// Create height map
	for row := height - 1; row >= 0; row-- {
		for i, val := range data {
			normalized := int(val / maxVal * float64(height))
			
			if row == normalized {
				// Peak of heartbeat
				if i > 0 && i < len(data)-1 {
					prevNorm := int(data[i-1] / maxVal * float64(height))
					nextNorm := int(data[i+1] / maxVal * float64(height))
					
					if prevNorm < normalized && nextNorm < normalized {
						// Peak
						output.WriteRune(upChar)
					} else if prevNorm > normalized && nextNorm > normalized {
						// Valley
						output.WriteRune(downChar)
					} else {
						output.WriteRune(flatChar)
					}
				} else {
					output.WriteRune(flatChar)
				}
			} else if row == 0 {
				// Baseline
				output.WriteRune('─')
			} else {
				output.WriteRune(' ')
			}
		}
		output.WriteString("\n")
	}
}

// drawPulse draws a pulse-style graph
func (h *HeartbeatVisualization) drawPulse(output *strings.Builder, data []float64, height int, upChar, downChar rune) {
	if len(data) == 0 {
		return
	}
	
	// Normalize data
	maxVal := 0.0
	for _, v := range data {
		if v > maxVal {
			maxVal = v
		}
	}
	if maxVal == 0 {
		maxVal = 1
	}
	
	for row := height - 1; row >= 0; row-- {
		for i, val := range data {
			normalized := int(val / maxVal * float64(height))
			
			if row <= normalized {
				if i%2 == 0 {
					output.WriteRune(upChar)
				} else {
					output.WriteRune(downChar)
				}
			} else if row == 0 {
				output.WriteRune('─')
			} else {
				output.WriteRune(' ')
			}
		}
		output.WriteString("\n")
	}
}

// drawLossIndicators draws packet loss indicators
func (h *HeartbeatVisualization) drawLossIndicators(output *strings.Builder, data []float64) {
	for _, loss := range data {
		if loss > 0 {
			output.WriteString("▪ ")
		} else {
			output.WriteString("  ")
		}
	}
	output.WriteString("\n")
	output.WriteString(strings.Repeat("─", len(data)*2))
}

// calculateHealth returns a health status string
func (h *HeartbeatVisualization) calculateHealth(latency, packets float64, lossHistory []float64) string {
	// Calculate loss percentage
	lossCount := 0.0
	for _, loss := range lossHistory {
		if loss > 0 {
			lossCount++
		}
	}
	lossPercent := 0.0
	if len(lossHistory) > 0 {
		lossPercent = lossCount / float64(len(lossHistory)) * 100
	}
	
	// Determine health status
	if latency < 50 && lossPercent < 1 {
		return "[green]████████ EXCELLENT[white]"
	} else if latency < 100 && lossPercent < 5 {
		return "[green]██████░░ GOOD[white]"
	} else if latency < 200 && lossPercent < 10 {
		return "[yellow]████░░░░ FAIR[white]"
	} else {
		return "[red]██░░░░░░ POOR[white]"
	}
}

// GetMinSize returns minimum size requirements
func (h *HeartbeatVisualization) GetMinSize() (width, height int) {
	return 80, 25
}