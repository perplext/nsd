package ui

import (
	"fmt"
	"math"
	"strings"

	"github.com/rivo/tview"
	"github.com/perplext/nsd/pkg/netcap"
	"github.com/perplext/nsd/pkg/utils"
)

// SpeedometerVisualization shows bandwidth as a speedometer gauge
type SpeedometerVisualization struct {
	BaseVisualization
	maxBandwidth   float64 // Maximum bandwidth in bytes/sec
	currentSpeed   float64
	inSpeed        float64
	outSpeed       float64
	history        []float64
	maxHistory     int
}

// NewSpeedometerVisualization creates a new speedometer visualization
func NewSpeedometerVisualization() Visualization {
	s := &SpeedometerVisualization{
		maxBandwidth: 100 * 1024 * 1024, // 100 Mbps default
		maxHistory:   20,
		history:      make([]float64, 0, 20),
	}
	s.textView = tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(false)
	s.textView.SetBorder(true).
		SetTitle("Bandwidth Speedometer")
	return s
}

// GetID returns the unique identifier
func (s *SpeedometerVisualization) GetID() string {
	return "speedometer"
}

// GetName returns the display name
func (s *SpeedometerVisualization) GetName() string {
	return "Bandwidth Speedometer"
}

// GetDescription returns a description
func (s *SpeedometerVisualization) GetDescription() string {
	return "Gauge-style bandwidth utilization display"
}

// CreateView creates the view
func (s *SpeedometerVisualization) CreateView() tview.Primitive {
	return s.textView
}

// Update updates the visualization
func (s *SpeedometerVisualization) Update(monitor *netcap.NetworkMonitor) {
	s.monitor = monitor
	
	// Get current bandwidth usage
	stats := monitor.GetInterfaceStats()
	var totalIn, totalOut uint64
	
	for _, stat := range stats {
		totalIn += stat.BytesIn
		totalOut += stat.BytesOut
	}
	
	// Calculate current speeds (this is simplified - real implementation would track deltas)
	s.inSpeed = float64(totalIn) / 10   // Simulated rate
	s.outSpeed = float64(totalOut) / 10 // Simulated rate
	s.currentSpeed = s.inSpeed + s.outSpeed
	
	// Update history
	s.history = append(s.history, s.currentSpeed)
	if len(s.history) > s.maxHistory {
		s.history = s.history[1:]
	}
	
	// Auto-adjust max if needed
	if s.currentSpeed > s.maxBandwidth*0.9 {
		s.maxBandwidth = s.currentSpeed * 1.5
	}
	
	// Draw the speedometer
	var output strings.Builder
	
	// Draw the gauge
	s.drawGauge(&output)
	
	// Current speed display
	output.WriteString("\n\n")
	speedMbps := s.currentSpeed * 8 / 1024 / 1024
	output.WriteString(fmt.Sprintf("         [yellow]◉ %.1f Mbps[white]\n", speedMbps))
	
	// In/Out breakdown
	output.WriteString("\n")
	output.WriteString(fmt.Sprintf("    ↓ In:  [green]%s/s[white]\n", utils.FormatBytes(uint64(s.inSpeed))))
	output.WriteString(fmt.Sprintf("    ↑ Out: [blue]%s/s[white]\n", utils.FormatBytes(uint64(s.outSpeed))))
	
	// Utilization percentage
	utilization := (s.currentSpeed / s.maxBandwidth) * 100
	output.WriteString(fmt.Sprintf("\n    Utilization: %.1f%%\n", utilization))
	
	// Mini sparkline history
	output.WriteString("\n    History: ")
	s.drawMiniSparkline(&output)
	
	s.textView.SetText(output.String())
}

// drawGauge draws the speedometer gauge
func (s *SpeedometerVisualization) drawGauge(output *strings.Builder) {
	// Gauge parameters
	width := 41
	height := 12
	centerX := width / 2
	centerY := height - 2
	radius := 15
	
	// Create grid
	grid := make([][]rune, height)
	for i := range grid {
		grid[i] = make([]rune, width)
		for j := range grid[i] {
			grid[i][j] = ' '
		}
	}
	
	// Draw gauge arc
	startAngle := math.Pi       // 180 degrees (left)
	endAngle := 0.0            // 0 degrees (right)
	steps := 40
	
	for i := 0; i <= steps; i++ {
		angle := startAngle + (endAngle-startAngle)*float64(i)/float64(steps)
		x := centerX + int(float64(radius)*math.Cos(angle))
		y := centerY - int(float64(radius)*math.Sin(angle)/2) // Compensate for aspect ratio
		
		if x >= 0 && x < width && y >= 0 && y < height {
			grid[y][x] = '─'
		}
	}
	
	// Draw scale markers
	scalePositions := []float64{0, 0.25, 0.5, 0.75, 1.0}
	scaleLabels := []string{"0%", "25%", "50%", "75%", "100%"}
	
	for i, pos := range scalePositions {
		angle := startAngle + (endAngle-startAngle)*pos
		x := centerX + int(float64(radius-2)*math.Cos(angle))
		y := centerY - int(float64(radius-2)*math.Sin(angle)/2)
		
		if x >= 0 && x < width && y >= 0 && y < height {
			grid[y][x] = '│'
		}
		
		// Label position
		labelX := centerX + int(float64(radius+3)*math.Cos(angle))
		labelY := centerY - int(float64(radius+3)*math.Sin(angle)/2)
		
		if labelX >= 0 && labelX+len(scaleLabels[i]) < width && labelY >= 0 && labelY < height {
			for j, ch := range scaleLabels[i] {
				if labelX+j < width {
					grid[labelY][labelX+j] = ch
				}
			}
		}
	}
	
	// Draw filled gauge based on current speed
	fillRatio := s.currentSpeed / s.maxBandwidth
	if fillRatio > 1.0 {
		fillRatio = 1.0
	}
	
	fillSteps := int(float64(steps) * fillRatio)
	for i := 0; i <= fillSteps; i++ {
		angle := startAngle + (endAngle-startAngle)*float64(i)/float64(steps)
		
		for r := radius - 5; r < radius; r++ {
			x := centerX + int(float64(r)*math.Cos(angle))
			y := centerY - int(float64(r)*math.Sin(angle)/2)
			
			if x >= 0 && x < width && y >= 0 && y < height {
				// Color based on speed
				if fillRatio < 0.5 {
					grid[y][x] = '░'
				} else if fillRatio < 0.75 {
					grid[y][x] = '▒'
				} else if fillRatio < 0.9 {
					grid[y][x] = '▓'
				} else {
					grid[y][x] = '█'
				}
			}
		}
	}
	
	// Draw needle
	needleAngle := startAngle + (endAngle-startAngle)*fillRatio
	for r := 3; r < radius-5; r++ {
		x := centerX + int(float64(r)*math.Cos(needleAngle))
		y := centerY - int(float64(r)*math.Sin(needleAngle)/2)
		
		if x >= 0 && x < width && y >= 0 && y < height {
			grid[y][x] = '▬'
		}
	}
	
	// Center point
	if centerY >= 0 && centerY < height && centerX >= 0 && centerX < width {
		grid[centerY][centerX] = '◉'
	}
	
	// Convert grid to string with colors
	for _, row := range grid {
		for _, ch := range row {
			if ch == '█' || ch == '▓' {
				if fillRatio > 0.9 {
					output.WriteString("[red]")
				} else if fillRatio > 0.75 {
					output.WriteString("[yellow]")
				} else {
					output.WriteString("[green]")
				}
				output.WriteRune(ch)
				output.WriteString("[white]")
			} else if ch == '▒' || ch == '░' {
				output.WriteString("[green]")
				output.WriteRune(ch)
				output.WriteString("[white]")
			} else if ch == '▬' {
				output.WriteString("[yellow]")
				output.WriteRune(ch)
				output.WriteString("[white]")
			} else {
				output.WriteRune(ch)
			}
		}
		output.WriteString("\n")
	}
}

// drawMiniSparkline draws a small sparkline of speed history
func (s *SpeedometerVisualization) drawMiniSparkline(output *strings.Builder) {
	if len(s.history) == 0 {
		return
	}
	
	chars := []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}
	
	maxVal := 0.0
	for _, v := range s.history {
		if v > maxVal {
			maxVal = v
		}
	}
	
	if maxVal == 0 {
		maxVal = 1
	}
	
	for _, val := range s.history {
		index := int((val / maxVal) * float64(len(chars)-1))
		if index >= len(chars) {
			index = len(chars) - 1
		}
		output.WriteRune(chars[index])
	}
}

// GetMinSize returns minimum size requirements
func (s *SpeedometerVisualization) GetMinSize() (width, height int) {
	return 45, 20
}