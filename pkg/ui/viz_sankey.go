package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rivo/tview"
	"github.com/user/nsd/pkg/netcap"
	"github.com/user/nsd/pkg/utils"
)

// SankeyVisualization shows network flow as a Sankey diagram
type SankeyVisualization struct {
	BaseVisualization
	flows map[string]uint64 // key: "src->dst", value: bytes
}

// NewSankeyVisualization creates a new Sankey visualization
func NewSankeyVisualization() Visualization {
	s := &SankeyVisualization{
		flows: make(map[string]uint64),
	}
	s.textView = tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(false)
	s.textView.SetBorder(true).
		SetTitle("Network Flow Sankey")
	return s
}

// GetID returns the unique identifier
func (s *SankeyVisualization) GetID() string {
	return "sankey"
}

// GetName returns the display name
func (s *SankeyVisualization) GetName() string {
	return "Network Flow Sankey"
}

// GetDescription returns a description
func (s *SankeyVisualization) GetDescription() string {
	return "Visualizes traffic flow between sources and destinations"
}

// CreateView creates the view
func (s *SankeyVisualization) CreateView() tview.Primitive {
	return s.textView
}

// Update updates the visualization
func (s *SankeyVisualization) Update(monitor *netcap.NetworkMonitor) {
	s.monitor = monitor
	
	// Clear flows
	s.flows = make(map[string]uint64)
	
	// Get connections and aggregate flows
	var connections []*netcap.Connection
	for interfaceName := range monitor.Interfaces {
		connections = append(connections, monitor.GetConnections(interfaceName)...)
	}
	srcMap := make(map[string]map[string]uint64) // src -> dst -> bytes
	
	for _, conn := range connections {
		src := conn.SrcIP.String()
		dst := fmt.Sprintf("%s (%d)", getServiceName(conn), conn.DstPort)
		
		if srcMap[src] == nil {
			srcMap[src] = make(map[string]uint64)
		}
		srcMap[src][dst] += conn.Size
	}
	
	// Sort sources by total traffic
	type srcFlow struct {
		src   string
		total uint64
		dests map[string]uint64
	}
	
	var sources []srcFlow
	for src, dests := range srcMap {
		var total uint64
		for _, bytes := range dests {
			total += bytes
		}
		sources = append(sources, srcFlow{src, total, dests})
	}
	
	sort.Slice(sources, func(i, j int) bool {
		return sources[i].total > sources[j].total
	})
	
	// Limit to top 10 sources
	if len(sources) > 10 {
		sources = sources[:10]
	}
	
	// Build the diagram
	var output strings.Builder
	
	// Find max destination name length for alignment
	maxDestLen := 0
	for _, src := range sources {
		for dst := range src.dests {
			if len(dst) > maxDestLen {
				maxDestLen = len(dst)
			}
		}
	}
	
	// Draw the flows
	for i, src := range sources {
		// Source IP
		srcDisplay := src.src
		if len(srcDisplay) > 15 {
			srcDisplay = srcDisplay[:15]
		}
		
		// Sort destinations by traffic
		type destFlow struct {
			dst   string
			bytes uint64
		}
		var dests []destFlow
		for dst, bytes := range src.dests {
			dests = append(dests, destFlow{dst, bytes})
		}
		sort.Slice(dests, func(i, j int) bool {
			return dests[i].bytes > dests[j].bytes
		})
		
		// Limit destinations per source
		if len(dests) > 3 {
			dests = dests[:3]
		}
		
		// Draw connections
		for j, dest := range dests {
			// Calculate bar width based on traffic
			barWidth := int(float64(dest.bytes) / float64(src.total) * 20)
			if barWidth < 1 {
				barWidth = 1
			}
			
			bar := strings.Repeat("█", barWidth)
			
			// Format the line
			var line string
			if j == 0 {
				// First destination - show source
				line = fmt.Sprintf("%-15s ═══╗", srcDisplay)
			} else if j == len(dests)-1 && i < len(sources)-1 {
				// Last destination - prepare for next source
				line = fmt.Sprintf("                ═╦═╝")
			} else {
				// Middle destinations
				line = fmt.Sprintf("                ═╬══")
			}
			
			// Add destination and traffic bar
			color := s.getFlowColor(dest.bytes, src.total)
			line += fmt.Sprintf(" ╠═══> %-*s %s%s[white] %s",
				maxDestLen,
				dest.dst,
				color,
				bar,
				utils.FormatBytes(dest.bytes))
			
			output.WriteString(line + "\n")
		}
		
		if i < len(sources)-1 {
			output.WriteString("\n")
		}
	}
	
	s.textView.SetText(output.String())
}

// getFlowColor returns a color based on traffic percentage
func (s *SankeyVisualization) getFlowColor(bytes, total uint64) string {
	percent := float64(bytes) / float64(total)
	switch {
	case percent > 0.5:
		return "[red]"
	case percent > 0.3:
		return "[yellow]"
	case percent > 0.1:
		return "[green]"
	default:
		return "[blue]"
	}
}

// getServiceName returns a friendly service name
func getServiceName(conn *netcap.Connection) string {
	if conn.Service != "" && conn.Service != "Unknown" {
		return conn.Service
	}
	
	// Try to determine from port
	switch conn.DstPort {
	case 80:
		return "HTTP"
	case 443:
		return "HTTPS"
	case 22:
		return "SSH"
	case 53:
		return "DNS"
	case 25, 587:
		return "Email"
	case 3306:
		return "MySQL"
	case 5432:
		return "PostgreSQL"
	case 6379:
		return "Redis"
	case 27017:
		return "MongoDB"
	default:
		if conn.DstIP.IsPrivate() {
			return "Local"
		}
		return "External"
	}
}

// GetMinSize returns minimum size requirements
func (s *SankeyVisualization) GetMinSize() (width, height int) {
	return 60, 20
}