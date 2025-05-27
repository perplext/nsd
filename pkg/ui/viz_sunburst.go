package ui

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/rivo/tview"
	"github.com/user/nsd/pkg/netcap"
)

// SunburstVisualization shows connection states in a hierarchical sunburst
type SunburstVisualization struct {
	BaseVisualization
}

// NewSunburstVisualization creates a new sunburst visualization
func NewSunburstVisualization() Visualization {
	s := &SunburstVisualization{}
	s.textView = tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(false)
	s.textView.SetBorder(true).
		SetTitle("Connection State Sunburst")
	return s
}

// GetID returns the unique identifier
func (s *SunburstVisualization) GetID() string {
	return "sunburst"
}

// GetName returns the display name
func (s *SunburstVisualization) GetName() string {
	return "Connection Sunburst"
}

// GetDescription returns a description
func (s *SunburstVisualization) GetDescription() string {
	return "Hierarchical view of connections by state/protocol/service"
}

// CreateView creates the view
func (s *SunburstVisualization) CreateView() tview.Primitive {
	return s.textView
}

// Update updates the visualization
func (s *SunburstVisualization) Update(monitor *netcap.NetworkMonitor) {
	s.monitor = monitor
	
	// Get connections and organize hierarchically
	var connections []*netcap.Connection
	for interfaceName := range monitor.Interfaces {
		connections = append(connections, monitor.GetConnections(interfaceName)...)
	}
	
	// Build hierarchy: State -> Protocol -> Service
	hierarchy := make(map[string]map[string]map[string]int)
	
	for _, conn := range connections {
		state := s.getConnectionState(conn)
		protocol := conn.Protocol
		service := getServiceName(conn)
		
		if hierarchy[state] == nil {
			hierarchy[state] = make(map[string]map[string]int)
		}
		if hierarchy[state][protocol] == nil {
			hierarchy[state][protocol] = make(map[string]int)
		}
		hierarchy[state][protocol][service]++
	}
	
	// Draw the sunburst
	width, height := 60, 30
	centerX, centerY := width/2, height/2
	
	grid := make([][]rune, height)
	for i := range grid {
		grid[i] = make([]rune, width)
		for j := range grid[i] {
			grid[i][j] = ' '
		}
	}
	
	// Draw concentric rings
	s.drawSunburst(grid, hierarchy, centerX, centerY)
	
	// Convert grid to string
	var output strings.Builder
	for _, row := range grid {
		output.WriteString(string(row) + "\n")
	}
	
	// Add legend
	output.WriteString("\n[white]Connection States:\n")
	
	totalConns := len(connections)
	for state, protocols := range hierarchy {
		stateCount := 0
		for _, services := range protocols {
			for _, count := range services {
				stateCount += count
			}
		}
		
		percentage := float64(stateCount) / float64(totalConns) * 100
		bar := strings.Repeat("█", int(percentage/5))
		color := s.getStateColor(state)
		
		output.WriteString(fmt.Sprintf("%s%-12s %s %5.1f%% (%d)[white]\n",
			color, state, bar, percentage, stateCount))
		
		// Top protocols for this state
		for protocol, services := range protocols {
			protocolCount := 0
			for _, count := range services {
				protocolCount += count
			}
			if protocolCount > 0 {
				output.WriteString(fmt.Sprintf("  └─ %s: %d\n", protocol, protocolCount))
			}
		}
	}
	
	s.textView.SetText(output.String())
}

// drawSunburst draws the sunburst diagram
func (s *SunburstVisualization) drawSunburst(grid [][]rune, hierarchy map[string]map[string]map[string]int, centerX, centerY int) {
	// Center
	s.drawText(grid, centerX-1, centerY, "CONN")
	
	// Calculate total for angles
	total := 0
	for _, protocols := range hierarchy {
		for _, services := range protocols {
			for _, count := range services {
				total += count
			}
		}
	}
	
	if total == 0 {
		return
	}
	
	// Draw rings
	innerRadius := 5
	middleRadius := 10
	outerRadius := 14
	
	startAngle := 0.0
	
	// State ring (inner)
	for state, protocols := range hierarchy {
		stateCount := 0
		for _, services := range protocols {
			for _, count := range services {
				stateCount += count
			}
		}
		
		angle := float64(stateCount) / float64(total) * 2 * math.Pi
		s.drawArc(grid, centerX, centerY, innerRadius, middleRadius-1, startAngle, startAngle+angle, s.getStateChar(state))
		
		// Protocol ring (middle)
		protocolStart := startAngle
		for protocol, services := range protocols {
			protocolCount := 0
			for _, count := range services {
				protocolCount += count
			}
			
			protocolAngle := float64(protocolCount) / float64(total) * 2 * math.Pi
			s.drawArc(grid, centerX, centerY, middleRadius, outerRadius-1, protocolStart, protocolStart+protocolAngle, s.getProtocolChar(protocol))
			
			protocolStart += protocolAngle
		}
		
		startAngle += angle
	}
	
	// Draw separators
	s.drawRadialLines(grid, centerX, centerY, innerRadius, outerRadius)
}

// drawArc draws an arc segment
func (s *SunburstVisualization) drawArc(grid [][]rune, cx, cy, innerR, outerR int, startAngle, endAngle float64, char rune) {
	steps := 100
	for i := 0; i <= steps; i++ {
		angle := startAngle + (endAngle-startAngle)*float64(i)/float64(steps)
		
		for r := innerR; r <= outerR; r++ {
			x := cx + int(float64(r)*math.Cos(angle))
			y := cy + int(float64(r)*math.Sin(angle)/2) // Aspect ratio
			
			if x >= 0 && x < len(grid[0]) && y >= 0 && y < len(grid) {
				grid[y][x] = char
			}
		}
	}
}

// drawRadialLines draws lines from center
func (s *SunburstVisualization) drawRadialLines(grid [][]rune, cx, cy, innerR, outerR int) {
	angles := []float64{0, math.Pi/2, math.Pi, 3*math.Pi/2}
	
	for _, angle := range angles {
		for r := innerR; r <= outerR; r++ {
			x := cx + int(float64(r)*math.Cos(angle))
			y := cy + int(float64(r)*math.Sin(angle)/2)
			
			if x >= 0 && x < len(grid[0]) && y >= 0 && y < len(grid) {
				if math.Abs(math.Sin(angle)) > 0.5 {
					grid[y][x] = '│'
				} else {
					grid[y][x] = '─'
				}
			}
		}
	}
}

// drawText draws text at position
func (s *SunburstVisualization) drawText(grid [][]rune, x, y int, text string) {
	for i, ch := range text {
		if x+i >= 0 && x+i < len(grid[0]) && y >= 0 && y < len(grid) {
			grid[y][x+i] = ch
		}
	}
}

// getConnectionState determines connection state
func (s *SunburstVisualization) getConnectionState(conn *netcap.Connection) string {
	// Simplified state detection based on recent activity
	if time.Since(conn.LastSeen) < 30*time.Second && conn.Packets > 0 {
		return "ESTABLISHED"
	}
	return "CLOSED"
}

// getStateChar returns a character for a state
func (s *SunburstVisualization) getStateChar(state string) rune {
	switch state {
	case "ESTABLISHED":
		return '█'
	case "SYN_SENT", "SYN_RECV":
		return '▓'
	case "CLOSED", "TIME_WAIT":
		return '▒'
	default:
		return '░'
	}
}

// getProtocolChar returns a character for a protocol
func (s *SunburstVisualization) getProtocolChar(protocol string) rune {
	switch protocol {
	case "TCP":
		return '▓'
	case "UDP":
		return '▒'
	default:
		return '░'
	}
}

// getStateColor returns color for a state
func (s *SunburstVisualization) getStateColor(state string) string {
	switch state {
	case "ESTABLISHED":
		return "[green]"
	case "SYN_SENT", "SYN_RECV":
		return "[yellow]"
	case "CLOSED", "TIME_WAIT":
		return "[red]"
	default:
		return "[white]"
	}
}

// GetMinSize returns minimum size requirements
func (s *SunburstVisualization) GetMinSize() (width, height int) {
	return 60, 35
}