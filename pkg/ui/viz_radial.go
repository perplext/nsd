package ui

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/rivo/tview"
	"github.com/perplext/nsd/pkg/netcap"
)

// RadialConnectionVisualization shows connections in a radial layout
type RadialConnectionVisualization struct {
	BaseVisualization
}

// NewRadialConnectionVisualization creates a new radial visualization
func NewRadialConnectionVisualization() Visualization {
	r := &RadialConnectionVisualization{}
	r.textView = tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(false)
	r.textView.SetBorder(true).
		SetTitle("Radial Connection Graph")
	return r
}

// GetID returns the unique identifier
func (r *RadialConnectionVisualization) GetID() string {
	return "radial"
}

// GetName returns the display name
func (r *RadialConnectionVisualization) GetName() string {
	return "Radial Connection Graph"
}

// GetDescription returns a description
func (r *RadialConnectionVisualization) GetDescription() string {
	return "Shows connections radiating from your host"
}

// CreateView creates the view
func (r *RadialConnectionVisualization) CreateView() tview.Primitive {
	return r.textView
}

// Update updates the visualization
func (r *RadialConnectionVisualization) Update(monitor *netcap.NetworkMonitor) {
	r.monitor = monitor
	
	// Get connections grouped by service
	var connections []*netcap.Connection
	for interfaceName := range monitor.Interfaces {
		connections = append(connections, monitor.GetConnections(interfaceName)...)
	}
	serviceMap := make(map[string][]*netcap.Connection)
	
	for _, conn := range connections {
		service := getServiceName(conn)
		serviceMap[service] = append(serviceMap[service], conn)
	}
	
	// Sort services by connection count
	type serviceInfo struct {
		name  string
		count int
		bytes uint64
	}
	
	var services []serviceInfo
	for name, conns := range serviceMap {
		var totalBytes uint64
		for _, conn := range conns {
			totalBytes += conn.Size
		}
		services = append(services, serviceInfo{name, len(conns), totalBytes})
	}
	
	sort.Slice(services, func(i, j int) bool {
		return services[i].count > services[j].count
	})
	
	// Limit to top 8 services for radial display
	if len(services) > 8 {
		services = services[:8]
	}
	
	// Create the radial visualization
	width, height := 50, 25
	grid := make([][]rune, height)
	for i := range grid {
		grid[i] = make([]rune, width)
		for j := range grid[i] {
			grid[i][j] = ' '
		}
	}
	
	// Center point
	centerX, centerY := width/2, height/2
	
	// Draw center (YOU)
	you := "┌─┴─┐\n│YOU│\n└─┬─┘"
	youLines := strings.Split(you, "\n")
	for i, line := range youLines {
		runes := []rune(line)
		for j, r := range runes {
			y := centerY - 1 + i
			x := centerX - 2 + j
			if y >= 0 && y < height && x >= 0 && x < width {
				grid[y][x] = r
			}
		}
	}
	
	// Draw connections radiating outward
	angleStep := 2 * math.Pi / float64(len(services))
	radius := float64(min(width, height)) / 3
	
	for i, service := range services {
		angle := float64(i) * angleStep
		
		// Calculate endpoint
		endX := centerX + int(radius*math.Cos(angle))
		endY := centerY + int(radius*math.Sin(angle)/2) // Compensate for aspect ratio
		
		// Draw line from center to service
		drawLine(grid, centerX, centerY, endX, endY)
		
		// Draw service box
		label := fmt.Sprintf("┌─────────┐\n│%-9s│\n└─────────┘", 
			truncate(service.name, 9))
		
		labelLines := strings.Split(label, "\n")
		startY := endY - 1
		startX := endX - 5
		
		for j, line := range labelLines {
			runes := []rune(line)
			for k, r := range runes {
				y := startY + j
				x := startX + k
				if y >= 0 && y < height && x >= 0 && x < width {
					grid[y][x] = r
				}
			}
		}
		
		// Add connection count
		countLabel := fmt.Sprintf("%d", service.count)
		countY := startY + 3
		countX := endX - len(countLabel)/2
		for j, r := range countLabel {
			x := countX + j
			if countY >= 0 && countY < height && x >= 0 && x < width {
				grid[countY][x] = rune(r)
			}
		}
	}
	
	// Convert grid to string
	var output strings.Builder
	for _, row := range grid {
		output.WriteString(string(row) + "\n")
	}
	
	// Add legend
	output.WriteString("\n[green]Services by Connection Count:[white]\n")
	for _, service := range services {
		bar := strings.Repeat("█", service.count/2+1)
		output.WriteString(fmt.Sprintf("%-12s %s%s[white] (%d)\n",
			service.name,
			r.getServiceColor(service.name),
			bar,
			service.count))
	}
	
	r.textView.SetText(output.String())
}

// drawLine draws a line between two points using ASCII characters
func drawLine(grid [][]rune, x1, y1, x2, y2 int) {
	dx := abs(x2 - x1)
	dy := abs(y2 - y1)
	
	var sx, sy int
	if x1 < x2 {
		sx = 1
	} else {
		sx = -1
	}
	if y1 < y2 {
		sy = 1
	} else {
		sy = -1
	}
	
	err := dx - dy
	x, y := x1, y1
	
	for {
		if x >= 0 && x < len(grid[0]) && y >= 0 && y < len(grid) {
			// Choose character based on direction
			if dx > dy {
				grid[y][x] = '─'
			} else {
				grid[y][x] = '│'
			}
		}
		
		if x == x2 && y == y2 {
			break
		}
		
		e2 := 2 * err
		if e2 > -dy {
			err -= dy
			x += sx
		}
		if e2 < dx {
			err += dx
			y += sy
		}
	}
}

// Helper functions
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func radialMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// getServiceColor returns a color for a service
func (r *RadialConnectionVisualization) getServiceColor(service string) string {
	switch service {
	case "HTTPS", "HTTP":
		return "[green]"
	case "SSH":
		return "[yellow]"
	case "DNS":
		return "[blue]"
	case "Email":
		return "[magenta]"
	case "Database":
		return "[red]"
	default:
		return "[white]"
	}
}

// GetMinSize returns minimum size requirements
func (r *RadialConnectionVisualization) GetMinSize() (width, height int) {
	return 50, 30
}