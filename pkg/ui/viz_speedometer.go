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

// gaugeParams holds parameters for gauge drawing
type gaugeParams struct {
	width      int
	height     int
	centerX    int
	centerY    int
	radius     int
	startAngle float64
	endAngle   float64
	steps      int
}

// drawGauge draws the speedometer gauge
func (s *SpeedometerVisualization) drawGauge(output *strings.Builder) {
	params := &gaugeParams{
		width:      41,
		height:     12,
		centerX:    41 / 2,
		centerY:    12 - 2,
		radius:     15,
		startAngle: math.Pi, // 180 degrees (left)
		endAngle:   0.0,     // 0 degrees (right)
		steps:      40,
	}
	
	grid := s.createEmptyGrid(params.width, params.height)
	s.drawGaugeArc(grid, params)
	s.drawScaleMarkers(grid, params)
	
	fillRatio := s.calculateFillRatio()
	s.drawFilledGauge(grid, params, fillRatio)
	s.drawNeedle(grid, params, fillRatio)
	s.drawCenterPoint(grid, params)
	
	s.renderGridToOutput(grid, output, fillRatio)
}

// createEmptyGrid creates an empty character grid
func (s *SpeedometerVisualization) createEmptyGrid(width, height int) [][]rune {
	grid := make([][]rune, height)
	for i := range grid {
		grid[i] = make([]rune, width)
		for j := range grid[i] {
			grid[i][j] = ' '
		}
	}
	return grid
}

// drawGaugeArc draws the main arc of the gauge
func (s *SpeedometerVisualization) drawGaugeArc(grid [][]rune, params *gaugeParams) {
	for i := 0; i <= params.steps; i++ {
		angle := s.calculateAngle(i, params.steps, params.startAngle, params.endAngle)
		x, y := s.polarToCartesian(angle, params.radius, params.centerX, params.centerY)
		
		if s.isInBounds(x, y, params.width, params.height) {
			grid[y][x] = '─'
		}
	}
}

// drawScaleMarkers draws scale markers and labels
func (s *SpeedometerVisualization) drawScaleMarkers(grid [][]rune, params *gaugeParams) {
	scalePositions := []float64{0, 0.25, 0.5, 0.75, 1.0}
	scaleLabels := []string{"0%", "25%", "50%", "75%", "100%"}
	
	for i, pos := range scalePositions {
		angle := params.startAngle + (params.endAngle-params.startAngle)*pos
		
		// Draw marker
		x, y := s.polarToCartesian(angle, params.radius-2, params.centerX, params.centerY)
		if s.isInBounds(x, y, params.width, params.height) {
			grid[y][x] = '│'
		}
		
		// Draw label
		s.drawLabel(grid, params, angle, scaleLabels[i])
	}
}

// drawLabel draws a text label at the specified angle
func (s *SpeedometerVisualization) drawLabel(grid [][]rune, params *gaugeParams, angle float64, label string) {
	labelX, labelY := s.polarToCartesian(angle, params.radius+3, params.centerX, params.centerY)
	
	if labelX >= 0 && labelX+len(label) < params.width && labelY >= 0 && labelY < params.height {
		for j, ch := range label {
			if labelX+j < params.width {
				grid[labelY][labelX+j] = ch
			}
		}
	}
}

// calculateFillRatio calculates the fill ratio based on current speed
func (s *SpeedometerVisualization) calculateFillRatio() float64 {
	fillRatio := s.currentSpeed / s.maxBandwidth
	if fillRatio > 1.0 {
		fillRatio = 1.0
	}
	return fillRatio
}

// drawFilledGauge draws the filled portion of the gauge
func (s *SpeedometerVisualization) drawFilledGauge(grid [][]rune, params *gaugeParams, fillRatio float64) {
	fillSteps := int(float64(params.steps) * fillRatio)
	fillChar := s.getFillCharacter(fillRatio)
	
	for i := 0; i <= fillSteps; i++ {
		angle := s.calculateAngle(i, params.steps, params.startAngle, params.endAngle)
		
		for r := params.radius - 5; r < params.radius; r++ {
			x, y := s.polarToCartesian(angle, r, params.centerX, params.centerY)
			
			if s.isInBounds(x, y, params.width, params.height) {
				grid[y][x] = fillChar
			}
		}
	}
}

// getFillCharacter returns the appropriate fill character based on fill ratio
func (s *SpeedometerVisualization) getFillCharacter(fillRatio float64) rune {
	if fillRatio < 0.5 {
		return '░'
	} else if fillRatio < 0.75 {
		return '▒'
	} else if fillRatio < 0.9 {
		return '▓'
	}
	return '█'
}

// drawNeedle draws the gauge needle
func (s *SpeedometerVisualization) drawNeedle(grid [][]rune, params *gaugeParams, fillRatio float64) {
	needleAngle := params.startAngle + (params.endAngle-params.startAngle)*fillRatio
	
	for r := 3; r < params.radius-5; r++ {
		x, y := s.polarToCartesian(needleAngle, r, params.centerX, params.centerY)
		
		if s.isInBounds(x, y, params.width, params.height) {
			grid[y][x] = '▬'
		}
	}
}

// drawCenterPoint draws the center point of the gauge
func (s *SpeedometerVisualization) drawCenterPoint(grid [][]rune, params *gaugeParams) {
	if s.isInBounds(params.centerX, params.centerY, params.width, params.height) {
		grid[params.centerY][params.centerX] = '◉'
	}
}

// renderGridToOutput converts the grid to a colored string
func (s *SpeedometerVisualization) renderGridToOutput(grid [][]rune, output *strings.Builder, fillRatio float64) {
	for _, row := range grid {
		for _, ch := range row {
			s.writeColoredChar(output, ch, fillRatio)
		}
		output.WriteString("\n")
	}
}

// writeColoredChar writes a character with appropriate color
func (s *SpeedometerVisualization) writeColoredChar(output *strings.Builder, ch rune, fillRatio float64) {
	switch ch {
	case '█', '▓':
		color := s.getSpeedColor(fillRatio)
		output.WriteString(color)
		output.WriteRune(ch)
		output.WriteString("[white]")
	case '▒', '░':
		output.WriteString("[green]")
		output.WriteRune(ch)
		output.WriteString("[white]")
	case '▬':
		output.WriteString("[yellow]")
		output.WriteRune(ch)
		output.WriteString("[white]")
	default:
		output.WriteRune(ch)
	}
}

// getSpeedColor returns the appropriate color based on speed
func (s *SpeedometerVisualization) getSpeedColor(fillRatio float64) string {
	if fillRatio > 0.9 {
		return "[red]"
	} else if fillRatio > 0.75 {
		return "[yellow]"
	}
	return "[green]"
}

// Helper functions

// calculateAngle calculates angle for a given step
func (s *SpeedometerVisualization) calculateAngle(step, totalSteps int, startAngle, endAngle float64) float64 {
	return startAngle + (endAngle-startAngle)*float64(step)/float64(totalSteps)
}

// polarToCartesian converts polar coordinates to cartesian
func (s *SpeedometerVisualization) polarToCartesian(angle float64, radius, centerX, centerY int) (int, int) {
	x := centerX + int(float64(radius)*math.Cos(angle))
	y := centerY - int(float64(radius)*math.Sin(angle)/2) // Compensate for aspect ratio
	return x, y
}

// isInBounds checks if coordinates are within grid bounds
func (s *SpeedometerVisualization) isInBounds(x, y, width, height int) bool {
	return x >= 0 && x < width && y >= 0 && y < height
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