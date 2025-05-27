package ui

import (
	"fmt"
	"math"
	"math/rand"
	"strings"
	"time"

	"github.com/rivo/tview"
	"github.com/user/nsd/pkg/netcap"
)

// ConstellationVisualization shows active ports as stars
type ConstellationVisualization struct {
	BaseVisualization
	stars []star
}

type star struct {
	x, y     int
	port     int
	size     int
	twinkle  int
}

// NewConstellationVisualization creates a new constellation visualization
func NewConstellationVisualization() Visualization {
	c := &ConstellationVisualization{
		stars: make([]star, 0),
	}
	c.textView = tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(false)
	c.textView.SetBorder(true).
		SetTitle("Port Activity Constellation")
	return c
}

// GetID returns the unique identifier
func (c *ConstellationVisualization) GetID() string {
	return "constellation"
}

// GetName returns the display name
func (c *ConstellationVisualization) GetName() string {
	return "Port Constellation"
}

// GetDescription returns a description
func (c *ConstellationVisualization) GetDescription() string {
	return "Visualize active ports as stars in the network sky"
}

// CreateView creates the view
func (c *ConstellationVisualization) CreateView() tview.Primitive {
	return c.textView
}

// Update updates the visualization
func (c *ConstellationVisualization) Update(monitor *netcap.NetworkMonitor) {
	c.monitor = monitor
	
	// Get active ports from connections
	var connections []*netcap.Connection
	for interfaceName := range monitor.GetInterfaceStats() {
		interfaceConns := monitor.GetConnections(interfaceName)
		connections = append(connections, interfaceConns...)
	}
	portActivity := make(map[int]int)
	
	for _, conn := range connections {
		// Assume connection is active if packets > 0 and recent activity
		if conn.Packets > 0 && time.Since(conn.LastSeen) < 30*time.Second {
			portActivity[int(conn.DstPort)]++
			portActivity[int(conn.SrcPort)]++
		}
	}
	
	// Create constellation
	width, height := 60, 25
	centerX, centerY := width/2, height/2
	
	// Update or create stars for active ports
	c.updateStars(portActivity, width, height, centerX, centerY)
	
	// Create grid
	grid := make([][]rune, height)
	for i := range grid {
		grid[i] = make([]rune, width)
		for j := range grid[i] {
			grid[i][j] = ' '
		}
	}
	
	// Draw YOUR HOST at center
	hostLabel := "YOUR HOST"
	for i, ch := range hostLabel {
		x := centerX - len(hostLabel)/2 + i
		if x >= 0 && x < width {
			grid[centerY][x] = ch
		}
	}
	
	// Draw stars
	for _, s := range c.stars {
		if s.x >= 0 && s.x < width && s.y >= 0 && s.y < height {
			// Choose star character based on size and twinkle
			char := c.getStarChar(s.size, s.twinkle)
			grid[s.y][s.x] = char
			
			// Draw port number near star for major ports
			if s.size > 2 {
				label := fmt.Sprintf("%d", s.port)
				labelY := s.y + 1
				labelX := s.x - len(label)/2
				
				if labelY < height {
					for i, ch := range label {
						x := labelX + i
						if x >= 0 && x < width && labelY >= 0 && labelY < height {
							if grid[labelY][x] == ' ' {
								grid[labelY][x] = ch
							}
						}
					}
				}
			}
		}
	}
	
	// Draw connections between related ports
	c.drawConnections(grid, width, height)
	
	// Convert grid to string
	var output strings.Builder
	for _, row := range grid {
		output.WriteString(string(row) + "\n")
	}
	
	// Legend
	output.WriteString("\n[white]Port Activity (connections):\n")
	
	// Sort ports by activity
	type portInfo struct {
		port  int
		count int
	}
	var ports []portInfo
	for port, count := range portActivity {
		ports = append(ports, portInfo{port, count})
	}
	
	// Sort by count
	for i := 0; i < len(ports); i++ {
		for j := i + 1; j < len(ports); j++ {
			if ports[j].count > ports[i].count {
				ports[i], ports[j] = ports[j], ports[i]
			}
		}
	}
	
	// Show top 10 ports
	if len(ports) > 10 {
		ports = ports[:10]
	}
	
	for _, p := range ports {
		service := c.getServiceForPort(p.port)
		starChar := c.getStarChar(c.getStarSize(p.count), 0)
		color := c.getPortColor(p.port)
		
		output.WriteString(fmt.Sprintf("%s%c %5d %-10s [%d connections][white]\n",
			color, starChar, p.port, service, p.count))
	}
	
	c.textView.SetText(output.String())
}

// updateStars updates star positions and properties
func (c *ConstellationVisualization) updateStars(portActivity map[int]int, width, height, centerX, centerY int) {
	// Update existing stars and remove inactive ones
	newStars := make([]star, 0)
	
	for port, activity := range portActivity {
		// Find existing star
		found := false
		for i, s := range c.stars {
			if s.port == port {
				// Update existing star
				c.stars[i].size = c.getStarSize(activity)
				c.stars[i].twinkle = (c.stars[i].twinkle + 1) % 3
				newStars = append(newStars, c.stars[i])
				found = true
				break
			}
		}
		
		if !found {
			// Create new star
			angle := float64(port%360) * math.Pi / 180
			distance := float64(10 + rand.Intn(10))
			
			x := centerX + int(distance*math.Cos(angle))
			y := centerY + int(distance*math.Sin(angle)/2) // Aspect ratio
			
			newStars = append(newStars, star{
				x:       x,
				y:       y,
				port:    port,
				size:    c.getStarSize(activity),
				twinkle: rand.Intn(3),
			})
		}
	}
	
	c.stars = newStars
}

// getStarSize returns star size based on activity
func (c *ConstellationVisualization) getStarSize(activity int) int {
	switch {
	case activity > 50:
		return 4
	case activity > 20:
		return 3
	case activity > 10:
		return 2
	case activity > 5:
		return 1
	default:
		return 0
	}
}

// getStarChar returns the character for a star
func (c *ConstellationVisualization) getStarChar(size, twinkle int) rune {
	switch size {
	case 4:
		return '★'
	case 3:
		return '✦'
	case 2:
		if twinkle == 0 {
			return '✦'
		}
		return '·'
	case 1:
		if twinkle == 0 {
			return '·'
		}
		return '.'
	default:
		return '·'
	}
}

// drawConnections draws lines between related ports
func (c *ConstellationVisualization) drawConnections(grid [][]rune, width, height int) {
	// Draw connections between common port pairs
	pairs := [][2]int{
		{80, 443},   // HTTP/HTTPS
		{20, 21},    // FTP
		{25, 587},   // SMTP
		{110, 995},  // POP3
		{143, 993},  // IMAP
	}
	
	for _, pair := range pairs {
		var s1, s2 *star
		for i := range c.stars {
			if c.stars[i].port == pair[0] {
				s1 = &c.stars[i]
			}
			if c.stars[i].port == pair[1] {
				s2 = &c.stars[i]
			}
		}
		
		if s1 != nil && s2 != nil {
			// Draw dotted line between stars
			steps := 10
			for i := 1; i < steps; i++ {
				x := s1.x + (s2.x-s1.x)*i/steps
				y := s1.y + (s2.y-s1.y)*i/steps
				
				if x >= 0 && x < width && y >= 0 && y < height && i%2 == 0 {
					if grid[y][x] == ' ' {
						grid[y][x] = '·'
					}
				}
			}
		}
	}
}

// getServiceForPort returns service name for a port
func (c *ConstellationVisualization) getServiceForPort(port int) string {
	services := map[int]string{
		20:    "FTP-DATA",
		21:    "FTP",
		22:    "SSH",
		23:    "TELNET",
		25:    "SMTP",
		53:    "DNS",
		80:    "HTTP",
		110:   "POP3",
		143:   "IMAP",
		443:   "HTTPS",
		445:   "SMB",
		587:   "SMTP-TLS",
		993:   "IMAPS",
		995:   "POP3S",
		1433:  "MSSQL",
		3306:  "MySQL",
		3389:  "RDP",
		5432:  "PostgreSQL",
		5900:  "VNC",
		6379:  "Redis",
		8080:  "HTTP-ALT",
		8443:  "HTTPS-ALT",
		9090:  "WebSocket",
		27017: "MongoDB",
	}
	
	if service, ok := services[port]; ok {
		return service
	}
	
	if port < 1024 {
		return "System"
	}
	return "Dynamic"
}

// getPortColor returns color for a port
func (c *ConstellationVisualization) getPortColor(port int) string {
	switch {
	case port == 80 || port == 443:
		return "[green]"
	case port == 22:
		return "[yellow]"
	case port == 21 || port == 23:
		return "[red]"
	case port < 1024:
		return "[blue]"
	default:
		return "[white]"
	}
}

// GetMinSize returns minimum size requirements
func (c *ConstellationVisualization) GetMinSize() (width, height int) {
	return 60, 30
}