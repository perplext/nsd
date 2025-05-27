package ui

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/rivo/tview"
	"github.com/user/nsd/pkg/netcap"
)

// MatrixRainVisualization shows packets falling Matrix-style
type MatrixRainVisualization struct {
	BaseVisualization
	columns      []matrixColumn
	width        int
	height       int
	lastUpdate   time.Time
	packetBuffer []matrixPacket
}

type matrixColumn struct {
	chars    []rune
	position int
	speed    int
	length   int
}

type matrixPacket struct {
	protocol string
	size     int
	time     time.Time
}

// NewMatrixRainVisualization creates a new Matrix rain visualization
func NewMatrixRainVisualization() Visualization {
	m := &MatrixRainVisualization{
		width:        80,
		height:       25,
		packetBuffer: make([]matrixPacket, 0, 100),
	}
	m.textView = tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(false)
	m.textView.SetBorder(true).
		SetTitle("Matrix Rain Packet Visualizer")
	
	// Initialize columns
	m.initializeColumns()
	
	return m
}

// GetID returns the unique identifier
func (m *MatrixRainVisualization) GetID() string {
	return "matrix"
}

// GetName returns the display name
func (m *MatrixRainVisualization) GetName() string {
	return "Matrix Rain"
}

// GetDescription returns a description
func (m *MatrixRainVisualization) GetDescription() string {
	return "Live packets falling Matrix-style"
}

// CreateView creates the view
func (m *MatrixRainVisualization) CreateView() tview.Primitive {
	return m.textView
}

// initializeColumns sets up the matrix columns
func (m *MatrixRainVisualization) initializeColumns() {
	m.columns = make([]matrixColumn, m.width/2) // Characters are 2 spaces wide
	
	for i := range m.columns {
		m.columns[i] = matrixColumn{
			chars:    make([]rune, m.height),
			position: rand.Intn(m.height),
			speed:    rand.Intn(3) + 1,
			length:   rand.Intn(10) + 5,
		}
		
		// Fill with spaces initially
		for j := range m.columns[i].chars {
			m.columns[i].chars[j] = ' '
		}
	}
}

// Update updates the visualization
func (m *MatrixRainVisualization) Update(monitor *netcap.NetworkMonitor) {
	m.monitor = monitor
	
	// Get recent packets
	packets := monitor.GetPacketBuffer()
	
	// Add new packets to buffer
	for _, pkt := range packets {
		if time.Since(pkt.Timestamp) < 2*time.Second {
			m.packetBuffer = append(m.packetBuffer, matrixPacket{
				protocol: pkt.Protocol,
				size:     int(pkt.Length),
				time:     pkt.Timestamp,
			})
		}
	}
	
	// Trim old packets
	if len(m.packetBuffer) > 100 {
		m.packetBuffer = m.packetBuffer[len(m.packetBuffer)-100:]
	}
	
	// Update matrix animation
	m.updateMatrix()
	
	// Render the matrix
	var output strings.Builder
	
	// Set black background style
	output.WriteString("[green]")
	
	// Draw the matrix
	for row := 0; row < m.height; row++ {
		for col := 0; col < len(m.columns); col++ {
			char := m.columns[col].chars[row]
			
			// Color based on position in trail
			pos := m.columns[col].position
			if row == pos {
				// Head of the trail - bright
				output.WriteString(fmt.Sprintf("[white]%c ", char))
			} else if row > pos-m.columns[col].length && row < pos {
				// Trail - varying green intensity
				intensity := float64(row-pos+m.columns[col].length) / float64(m.columns[col].length)
				if intensity > 0.7 {
					output.WriteString(fmt.Sprintf("[green]%c ", char))
				} else if intensity > 0.3 {
					output.WriteString(fmt.Sprintf("[darkgreen]%c ", char))
				} else {
					output.WriteString(fmt.Sprintf("[darkgreen]%c ", char))
				}
			} else {
				output.WriteString("  ")
			}
		}
		output.WriteString("\n")
	}
	
	// Reset color
	output.WriteString("[white]")
	
	// Protocol legend at bottom
	output.WriteString("\n[white]Recent Protocols: ")
	protocolCounts := make(map[string]int)
	for _, pkt := range m.packetBuffer {
		protocolCounts[pkt.protocol]++
	}
	
	for proto, count := range protocolCounts {
		color := m.getProtocolColor(proto)
		output.WriteString(fmt.Sprintf("%s%s:%d ", color, proto, count))
	}
	
	m.textView.SetText(output.String())
}

// updateMatrix updates the falling characters
func (m *MatrixRainVisualization) updateMatrix() {
	// Protocol characters
	protoChars := map[string][]rune{
		"TCP":  []rune("TCP4680"),
		"UDP":  []rune("UDP8053"),
		"ICMP": []rune("ICMP64"),
		"HTTP": []rune("HTTP80"),
		"DNS":  []rune("DNS53Q"),
		"SSH":  []rune("SSH22"),
	}
	
	// Update each column
	for i := range m.columns {
		// Move the trail down
		if time.Since(m.lastUpdate).Milliseconds() > int64(100/m.columns[i].speed) {
			m.columns[i].position++
			
			// Reset if at bottom
			if m.columns[i].position-m.columns[i].length > m.height {
				m.columns[i].position = 0
				m.columns[i].speed = rand.Intn(3) + 1
				m.columns[i].length = rand.Intn(10) + 5
			}
			
			// Add new character at head position
			if m.columns[i].position < m.height && m.columns[i].position >= 0 {
				// Choose character based on recent packets
				if len(m.packetBuffer) > 0 && rand.Float32() < 0.7 {
					// Use protocol character
					pkt := m.packetBuffer[rand.Intn(len(m.packetBuffer))]
					if chars, ok := protoChars[pkt.protocol]; ok {
						m.columns[i].chars[m.columns[i].position] = chars[rand.Intn(len(chars))]
					} else {
						m.columns[i].chars[m.columns[i].position] = rune('0' + rand.Intn(10))
					}
				} else {
					// Random character
					if rand.Float32() < 0.5 {
						m.columns[i].chars[m.columns[i].position] = rune('0' + rand.Intn(10))
					} else {
						m.columns[i].chars[m.columns[i].position] = rune('A' + rand.Intn(26))
					}
				}
			}
		}
	}
	
	m.lastUpdate = time.Now()
}

// getProtocolColor returns color for a protocol
func (m *MatrixRainVisualization) getProtocolColor(protocol string) string {
	switch protocol {
	case "TCP":
		return "[green]"
	case "UDP":
		return "[blue]"
	case "ICMP":
		return "[yellow]"
	case "HTTP", "HTTPS":
		return "[cyan]"
	case "DNS":
		return "[magenta]"
	default:
		return "[white]"
	}
}

// GetMinSize returns minimum size requirements
func (m *MatrixRainVisualization) GetMinSize() (width, height int) {
	return 80, 30
}