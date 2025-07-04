package graph

import (
	"fmt"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// DataPoint represents a single data point in the graph
type DataPoint struct {
	Value     float64
	Timestamp time.Time
}

// GraphStyle represents the rendering style of the graph
type GraphStyle int

const (
	// StyleBraille uses Unicode Braille patterns for smooth graphs
	StyleBraille GraphStyle = iota
	// StyleBlock uses block characters for traditional graphs
	StyleBlock
	// StyleTTY uses ASCII characters for compatibility
	StyleTTY
)

// Graph represents a time-series graph
type Graph struct {
	*tview.Box
	title         string
	data          []DataPoint
	maxPoints     int
	maxValue      float64
	autoScale     bool
	color         tcell.Color
	secondaryData []DataPoint
	secondaryColor tcell.Color
	mutex         sync.RWMutex
	unit          string
	lastUpdate    time.Time
	showLegend    bool
	primaryLabel  string
	secondaryLabel string
	gradientEnabled bool // static gradient shading enabled
	style          GraphStyle
	gradientColors []tcell.Color // pre-calculated gradient colors
}

// NewGraph creates a new graph
func NewGraph() *Graph {
	g := &Graph{
		Box:            tview.NewBox(),
		maxPoints:      120,
		data:           make([]DataPoint, 0, 120),
		secondaryData:  make([]DataPoint, 0, 120),
		autoScale:      true,
		color:          tcell.ColorGreen,
		secondaryColor: tcell.ColorBlue,
		unit:           "B/s",
		showLegend:     true,
		primaryLabel:   "In",
		secondaryLabel: "Out",
		gradientEnabled: true, // default on
		style:          StyleBraille, // default to Braille style
	}
	
	// Pre-calculate gradient colors
	g.calculateGradientColors()
	
	// Add some initial data points to make the graph visible immediately
	now := time.Now()
	for i := 0; i < 10; i++ {
		g.data = append(g.data, DataPoint{
			Value:     float64(i * 10),
			Timestamp: now.Add(time.Duration(-i) * time.Second),
		})
		g.secondaryData = append(g.secondaryData, DataPoint{
			Value:     float64((10-i) * 5),
			Timestamp: now.Add(time.Duration(-i) * time.Second),
		})
	}
	
	// Set a reasonable default max value
	g.maxValue = 100
	
	return g
}

// SetStyle sets the graph rendering style
func (g *Graph) SetStyle(style GraphStyle) *Graph {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.style = style
	return g
}

// calculateGradientColors pre-calculates gradient colors for performance
func (g *Graph) calculateGradientColors() {
	steps := 20
	g.gradientColors = make([]tcell.Color, steps)
	
	pr, pg, pb := g.color.RGB()
	sr, sg, sb := g.secondaryColor.RGB()
	
	for i := 0; i < steps; i++ {
		ratio := float64(i) / float64(steps-1)
		r := int32(float64(pr)*(1-ratio) + float64(sr)*ratio)
		gr := int32(float64(pg)*(1-ratio) + float64(sg)*ratio)
		b := int32(float64(pb)*(1-ratio) + float64(sb)*ratio)
		g.gradientColors[i] = tcell.NewRGBColor(r, gr, b)
	}
}

// getBrailleChar returns the appropriate Braille character for the given heights
// heights is an array of 2x4 values (0-3) representing the dots in a Braille cell
func getBrailleChar(heights [8]int) rune {
	// Braille Unicode block starts at 0x2800
	// Each dot position has a specific bit value:
	// 1 4
	// 2 5
	// 3 6
	// 7 8
	bitmap := 0
	dotValues := []int{0x01, 0x02, 0x04, 0x40, 0x08, 0x10, 0x20, 0x80}
	
	for i, height := range heights {
		if height > 0 {
			bitmap |= dotValues[i]
		}
	}
	
	return rune(0x2800 + bitmap)
}

// SetTitle sets the graph title
func (g *Graph) SetTitle(title string) *Graph {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.title = title
	return g
}

// SetColor sets the primary graph color
func (g *Graph) SetColor(color tcell.Color) *Graph {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.color = color
	g.calculateGradientColors() // recalculate gradients
	return g
}

// SetSecondaryColor sets the secondary graph color
func (g *Graph) SetSecondaryColor(color tcell.Color) *Graph {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.secondaryColor = color
	g.calculateGradientColors() // recalculate gradients
	return g
}

// SetMaxValue sets the maximum value for the y-axis
func (g *Graph) SetMaxValue(max float64) *Graph {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.maxValue = max
	g.autoScale = false
	return g
}

// SetAutoScale enables or disables auto-scaling
func (g *Graph) SetAutoScale(auto bool) *Graph {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.autoScale = auto
	return g
}

// SetUnit sets the unit for the y-axis
func (g *Graph) SetUnit(unit string) *Graph {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.unit = unit
	return g
}

// SetLabels sets the labels for the primary and secondary data
func (g *Graph) SetLabels(primary, secondary string) *Graph {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.primaryLabel = primary
	g.secondaryLabel = secondary
	return g
}

// ShowLegend enables or disables the legend
func (g *Graph) ShowLegend(show bool) *Graph {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.showLegend = show
	return g
}

// SetGradientEnabled toggles static gradient shading for the graph
func (g *Graph) SetGradientEnabled(enabled bool) *Graph {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.gradientEnabled = enabled
	return g
}

// GradientEnabled reports whether static gradient shading is enabled
func (g *Graph) GradientEnabled() bool {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.gradientEnabled
}

// AddPoint adds a data point to the graph
func (g *Graph) AddPoint(value float64) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	now := time.Now()
	g.data = append(g.data, DataPoint{Value: value, Timestamp: now})
	if len(g.data) > g.maxPoints {
		g.data = g.data[1:]
	}

	g.lastUpdate = now
	g.updateMaxValue()
}

// AddDualPoint adds a primary and secondary data point to the graph
func (g *Graph) AddDualPoint(primary, secondary float64) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	now := time.Now()
	
	// Add primary data point
	g.data = append(g.data, DataPoint{Value: primary, Timestamp: now})
	if len(g.data) > g.maxPoints {
		g.data = g.data[1:]
	}

	// Add secondary data point
	g.secondaryData = append(g.secondaryData, DataPoint{Value: secondary, Timestamp: now})
	if len(g.secondaryData) > g.maxPoints {
		g.secondaryData = g.secondaryData[1:]
	}

	g.lastUpdate = now
	g.updateMaxValue()
}

// updateMaxValue updates the maximum value if auto-scaling is enabled
func (g *Graph) updateMaxValue() {
	if !g.autoScale {
		return
	}

	maxVal := 0.0
	for _, point := range g.data {
		if point.Value > maxVal {
			maxVal = point.Value
		}
	}

	for _, point := range g.secondaryData {
		if point.Value > maxVal {
			maxVal = point.Value
		}
	}

	// Add a 10% buffer
	g.maxValue = maxVal * 1.1

	// If the max value is very small, set a minimum
	if g.maxValue < 10 {
		g.maxValue = 10
	}
}

// shadeBlock returns a shading glyph for a ratio [0..1]
func shadeBlock(ratio float64) rune {
	switch {
	case ratio < 0.1:
		return '·'
	case ratio < 0.3:
		return '░'
	case ratio < 0.6:
		return '▒'
	case ratio < 0.9:
		return '▓'
	default:
		return '█'
	}
}

// ShadeBlock returns a shading rune for a ratio [0..1], wrapping internal shadeBlock.
func ShadeBlock(ratio float64) rune {
	return shadeBlock(ratio)
}

// Draw draws the graph
func (g *Graph) Draw(screen tcell.Screen) {
	// Draw the box
	g.DrawForSubclass(screen, g)

	g.mutex.RLock()
	defer g.mutex.RUnlock()

	// Get the graph area
	x, y, width, height := g.GetInnerRect()
	if width <= 10 || height <= 3 {
		return
	}

	// Draw title
	if g.title != "" {
		tview.Print(screen, g.title, x, y, width, tview.AlignCenter, g.color)
		y++
		height--
	}

	// Reserve space for legend
	if g.showLegend {
		height--
	}

	// Calculate graph dimensions
	labelWidth := len(formatValue(g.maxValue) + g.unit) + 1
	graphX := x + labelWidth
	graphWidth := width - labelWidth - 1
	graphHeight := height - 1

	if graphWidth < 2 || graphHeight < 2 {
		return
	}

	// Draw y-axis labels
	// Top label
	maxLabel := formatValue(g.maxValue) + g.unit
	tview.Print(screen, maxLabel, x, y, labelWidth-1, tview.AlignRight, tcell.ColorGray)
	
	// Middle label
	if graphHeight > 4 {
		midLabel := formatValue(g.maxValue/2) + g.unit
		tview.Print(screen, midLabel, x, y+graphHeight/2, labelWidth-1, tview.AlignRight, tcell.ColorGray)
	}
	
	// Bottom label
	tview.Print(screen, "0"+g.unit, x, y+graphHeight-1, labelWidth-1, tview.AlignRight, tcell.ColorGray)

	// Draw axis lines
	axisStyle := tcell.StyleDefault.Foreground(tcell.ColorGray)
	// Vertical axis
	for i := 0; i < graphHeight; i++ {
		screen.SetContent(graphX-1, y+i, '│', nil, axisStyle)
	}
	// Horizontal axis
	screen.SetContent(graphX-1, y+graphHeight, '└', nil, axisStyle)
	for i := 0; i < graphWidth; i++ {
		screen.SetContent(graphX+i, y+graphHeight, '─', nil, axisStyle)
	}

	// Choose rendering method based on style
	switch g.style {
	case StyleBraille:
		g.drawBrailleGraph(screen, graphX, y, graphWidth, graphHeight)
	case StyleBlock:
		g.drawBlockGraph(screen, graphX, y, graphWidth, graphHeight)
	case StyleTTY:
		g.drawTTYGraph(screen, graphX, y, graphWidth, graphHeight)
	}

	// Draw legend
	if g.showLegend {
		legendY := y + graphHeight + 1
		legendText := fmt.Sprintf("[%s]█ %s[white]  [%s]█ %s", 
			ColorToHex(g.color), g.primaryLabel,
			ColorToHex(g.secondaryColor), g.secondaryLabel)
		tview.Print(screen, legendText, x, legendY, width, tview.AlignCenter, tcell.ColorWhite)
	}
}

// drawBrailleGraph draws the graph using Braille Unicode characters
func (g *Graph) drawBrailleGraph(screen tcell.Screen, x, y, width, height int) {
	if len(g.data) == 0 {
		return
	}

	// Each Braille character represents a 2x4 grid
	brailleWidth := width
	brailleHeight := height * 4

	// Create value buffers
	primaryValues := make([]float64, brailleWidth*2)
	secondaryValues := make([]float64, brailleWidth*2)

	// Sample data points
	for i := 0; i < brailleWidth*2; i++ {
		// Safe integer conversion with bounds checking
		idx := 0
		if brailleWidth*2-1 > 0 && len(g.data) > 0 {
			floatIdx := float64(i) / float64(brailleWidth*2-1) * float64(len(g.data)-1)
			if floatIdx >= 0 && floatIdx < float64(len(g.data)) {
				idx = int(floatIdx)
				if idx >= len(g.data) {
					idx = len(g.data) - 1
				}
			}
		}
		if idx < len(g.data) {
			primaryValues[i] = g.data[idx].Value
		}
		
		if len(g.secondaryData) > 0 {
			// Safe integer conversion with bounds checking
			idx2 := 0
			if brailleWidth*2-1 > 0 {
				floatIdx2 := float64(i) / float64(brailleWidth*2-1) * float64(len(g.secondaryData)-1)
				if floatIdx2 >= 0 && floatIdx2 < float64(len(g.secondaryData)) {
					idx2 = int(floatIdx2)
					if idx2 >= len(g.secondaryData) {
						idx2 = len(g.secondaryData) - 1
					}
				}
			}
			if idx2 < len(g.secondaryData) {
				secondaryValues[i] = g.secondaryData[idx2].Value
			}
		}
	}

	// Draw Braille characters
	for col := 0; col < brailleWidth; col++ {
		for row := 0; row < height; row++ {
			cellY := y + row
			cellX := x + col

			// Calculate heights for this Braille cell
			heights := [8]int{0, 0, 0, 0, 0, 0, 0, 0}
			
			// Process two columns of data for this character
			for subCol := 0; subCol < 2; subCol++ {
				dataIdx := col*2 + subCol
				if dataIdx >= len(primaryValues) {
					continue
				}

				// Primary data with safe conversion
				primaryHeight := 0
				if g.maxValue > 0 {
					heightRatio := primaryValues[dataIdx] / g.maxValue
					if heightRatio > 1.0 {
						heightRatio = 1.0
					} else if heightRatio < 0 {
						heightRatio = 0
					}
					primaryHeight = int(heightRatio * float64(brailleHeight))
					if primaryHeight > brailleHeight {
						primaryHeight = brailleHeight
					} else if primaryHeight < 0 {
						primaryHeight = 0
					}
				}

				// Secondary data
				secondaryHeight := 0
				if len(g.secondaryData) > 0 && dataIdx < len(secondaryValues) {
					// Safe conversion for secondary height
					if g.maxValue > 0 {
						heightRatio := secondaryValues[dataIdx] / g.maxValue
						if heightRatio > 1.0 {
							heightRatio = 1.0
						} else if heightRatio < 0 {
							heightRatio = 0
						}
						secondaryHeight = int(heightRatio * float64(brailleHeight))
						if secondaryHeight > brailleHeight {
							secondaryHeight = brailleHeight
						} else if secondaryHeight < 0 {
							secondaryHeight = 0
						}
					}
				}

				// Fill in the Braille dots for this column
				cellStartHeight := (height - row - 1) * 4
				for dot := 0; dot < 4; dot++ {
					dotHeight := cellStartHeight + dot
					dotIdx := subCol*4 + (3-dot)
					
					if dotHeight < primaryHeight || dotHeight < secondaryHeight {
						heights[dotIdx] = 1
					}
				}
			}

			// Get the Braille character
			ch := getBrailleChar(heights)
			
			// Determine color with gradient
			if ch != 0x2800 { // Not empty
				cellHeightRatio := float64(height-row-1) / float64(height-1)
				var color tcell.Color
				
				if g.gradientEnabled && len(g.gradientColors) > 0 {
					// Safe gradient index calculation
					gradIdx := 0
					if len(g.gradientColors) > 1 && cellHeightRatio >= 0 && cellHeightRatio <= 1.0 {
						fIdx := cellHeightRatio * float64(len(g.gradientColors)-1)
						gradIdx = int(fIdx)
						if gradIdx >= len(g.gradientColors) {
							gradIdx = len(g.gradientColors) - 1
						} else if gradIdx < 0 {
							gradIdx = 0
						}
					}
					color = g.gradientColors[gradIdx]
				} else {
					// Simple color based on which data is higher at this position
					avgPrimary := (primaryValues[col*2] + primaryValues[min(col*2+1, len(primaryValues)-1)]) / 2
					avgSecondary := float64(0)
					if len(secondaryValues) > 0 {
						avgSecondary = (secondaryValues[col*2] + secondaryValues[min(col*2+1, len(secondaryValues)-1)]) / 2
					}
					
					if avgPrimary >= avgSecondary {
						color = g.color
					} else {
						color = g.secondaryColor
					}
				}
				
				screen.SetContent(cellX, cellY, ch, nil, tcell.StyleDefault.Foreground(color))
			}
		}
	}
}

// drawBlockGraph draws the graph using block characters
func (g *Graph) drawBlockGraph(screen tcell.Screen, x, y, width, height int) {
	if len(g.data) == 0 {
		return
	}

	// blocks := []rune{' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

	for col := 0; col < width; col++ {
		// Sample data with safe conversion
		idx := 0
		if width > 1 && len(g.data) > 0 {
			floatIdx := float64(col) / float64(width-1) * float64(len(g.data)-1)
			if floatIdx >= 0 && floatIdx < float64(len(g.data)) {
				idx = int(floatIdx)
				if idx >= len(g.data) {
					idx = len(g.data) - 1
				}
			}
		}
		primaryValue := float64(0)
		if idx < len(g.data) {
			primaryValue = g.data[idx].Value
		}
		
		secondaryValue := float64(0)
		if len(g.secondaryData) > 0 && width > 1 {
			// Safe conversion for secondary data
			idx2 := 0
			floatIdx2 := float64(col) / float64(width-1) * float64(len(g.secondaryData)-1)
			if floatIdx2 >= 0 && floatIdx2 < float64(len(g.secondaryData)) {
				idx2 = int(floatIdx2)
				if idx2 >= len(g.secondaryData) {
					idx2 = len(g.secondaryData) - 1
				}
			}
			if idx2 < len(g.secondaryData) {
				secondaryValue = g.secondaryData[idx2].Value
			}
		}

		// Scale values with safe conversion
		primaryHeight := 0
		secondaryHeight := 0
		if g.maxValue > 0 {
			primaryRatio := primaryValue / g.maxValue
			if primaryRatio > 1.0 {
				primaryRatio = 1.0
			} else if primaryRatio < 0 {
				primaryRatio = 0
			}
			primaryHeight = int(primaryRatio * float64(height))
			if primaryHeight > height {
				primaryHeight = height
			}
			
			secondaryRatio := secondaryValue / g.maxValue
			if secondaryRatio > 1.0 {
				secondaryRatio = 1.0
			} else if secondaryRatio < 0 {
				secondaryRatio = 0
			}
			secondaryHeight = int(secondaryRatio * float64(height))
			if secondaryHeight > height {
				secondaryHeight = height
			}
		}

		// Draw column
		for row := 0; row < height; row++ {
			cellY := y + height - row - 1
			cellHeight := row

			var ch rune
			var color tcell.Color

			if cellHeight < primaryHeight && cellHeight < secondaryHeight {
				// Both data points at this height
				ch = '█'
				if g.gradientEnabled && len(g.gradientColors) > 0 && height > 1 {
					// Safe gradient index calculation
					gradIdx := 0
					floatIdx := float64(row) / float64(height-1) * float64(len(g.gradientColors)-1)
					if floatIdx >= 0 && floatIdx <= float64(len(g.gradientColors)-1) {
						gradIdx = int(floatIdx)
						if gradIdx >= len(g.gradientColors) {
							gradIdx = len(g.gradientColors) - 1
						}
					}
					color = g.gradientColors[gradIdx]
				} else {
					color = g.color
				}
			} else if cellHeight < primaryHeight {
				// Only primary
				ch = '█'
				color = g.color
			} else if cellHeight < secondaryHeight {
				// Only secondary
				ch = '█'
				color = g.secondaryColor
			} else {
				continue
			}

			screen.SetContent(x+col, cellY, ch, nil, tcell.StyleDefault.Foreground(color))
		}
	}
}

// drawTTYGraph draws the graph using ASCII characters
func (g *Graph) drawTTYGraph(screen tcell.Screen, x, y, width, height int) {
	if len(g.data) == 0 {
		return
	}

	for col := 0; col < width; col++ {
		// Sample data with safe conversion
		idx := 0
		if width > 1 && len(g.data) > 0 {
			floatIdx := float64(col) / float64(width-1) * float64(len(g.data)-1)
			if floatIdx >= 0 && floatIdx < float64(len(g.data)) {
				idx = int(floatIdx)
				if idx >= len(g.data) {
					idx = len(g.data) - 1
				}
			}
		}
		value := float64(0)
		if idx < len(g.data) {
			value = g.data[idx].Value
		}
		
		// Scale value with safe conversion
		scaledHeight := 0
		if g.maxValue > 0 && height > 1 {
			heightRatio := value / g.maxValue
			if heightRatio > 1.0 {
				heightRatio = 1.0
			} else if heightRatio < 0 {
				heightRatio = 0
			}
			scaledHeight = int(heightRatio * float64(height-1))
			if scaledHeight >= height {
				scaledHeight = height - 1
			} else if scaledHeight < 0 {
				scaledHeight = 0
			}
		}

		// Draw character
		cellY := y + height - scaledHeight - 1
		screen.SetContent(x+col, cellY, '*', nil, tcell.StyleDefault.Foreground(g.color))
		
		// Draw secondary data if available
		if len(g.secondaryData) > 0 && width > 1 {
			// Safe conversion for secondary data
			idx2 := 0
			floatIdx2 := float64(col) / float64(width-1) * float64(len(g.secondaryData)-1)
			if floatIdx2 >= 0 && floatIdx2 < float64(len(g.secondaryData)) {
				idx2 = int(floatIdx2)
				if idx2 >= len(g.secondaryData) {
					idx2 = len(g.secondaryData) - 1
				}
			}
			value2 := float64(0)
			if idx2 < len(g.secondaryData) {
				value2 = g.secondaryData[idx2].Value
			}
			
			scaledHeight2 := 0
			if g.maxValue > 0 && height > 1 {
				heightRatio2 := value2 / g.maxValue
				if heightRatio2 > 1.0 {
					heightRatio2 = 1.0
				} else if heightRatio2 < 0 {
					heightRatio2 = 0
				}
				scaledHeight2 = int(heightRatio2 * float64(height-1))
				if scaledHeight2 >= height {
					scaledHeight2 = height - 1
				} else if scaledHeight2 < 0 {
					scaledHeight2 = 0
				}
			}
			cellY2 := y + height - scaledHeight2 - 1
			if cellY2 != cellY {
				screen.SetContent(x+col, cellY2, '+', nil, tcell.StyleDefault.Foreground(g.secondaryColor))
			}
		}
	}
}

// formatValue formats a value with appropriate units
func formatValue(value float64) string {
	if value >= 1e9 {
		return fmt.Sprintf("%.1fG", value/1e9)
	} else if value >= 1e6 {
		return fmt.Sprintf("%.1fM", value/1e6)
	} else if value >= 1e3 {
		return fmt.Sprintf("%.1fK", value/1e3)
	}
	return fmt.Sprintf("%.1f", value)
}

// ColorToHex converts a tcell.Color to a hex string for tview
func ColorToHex(color tcell.Color) string {
	// Handle basic named colors for accurate hex mapping
	switch color {
	case tcell.ColorRed:
		return "#ff0000"
	case tcell.ColorGreen:
		return "#00ff00"
	case tcell.ColorBlue:
		return "#0000ff"
	case tcell.ColorWhite:
		return "#ffffff"
	case tcell.ColorBlack:
		return "#000000"
	}
	r, g, b := color.RGB()
	return fmt.Sprintf("#%02x%02x%02x", r, g, b)
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GraphWidget is a wrapper around Graph that implements the tview.Primitive interface
type GraphWidget struct {
	*Graph
	historyDuration time.Duration
	sampleInterval  time.Duration
	dataFunc        func() (float64, float64)
	stopChan        chan struct{}
	started         bool
	widgetMutex     sync.RWMutex
}

// NewGraphWidget creates a new graph widget
func NewGraphWidget() *GraphWidget {
	return &GraphWidget{
		Graph:           NewGraph(),
		historyDuration: 2 * time.Minute,
		sampleInterval:  1 * time.Second,
		stopChan:        make(chan struct{}),
	}
}

// SetDataFunc sets the function that provides data for the graph
func (gw *GraphWidget) SetDataFunc(f func() (float64, float64)) *GraphWidget {
	gw.widgetMutex.Lock()
	defer gw.widgetMutex.Unlock()
	gw.dataFunc = f
	return gw
}

// SetSampleInterval sets how often to sample data
func (gw *GraphWidget) SetSampleInterval(d time.Duration) *GraphWidget {
	gw.widgetMutex.Lock()
	defer gw.widgetMutex.Unlock()
	gw.sampleInterval = d
	return gw
}

// SetHistoryDuration sets how much history to keep
func (gw *GraphWidget) SetHistoryDuration(d time.Duration) *GraphWidget {
	gw.widgetMutex.Lock()
	defer gw.widgetMutex.Unlock()
	gw.historyDuration = d
	maxPoints := int(d / gw.sampleInterval)
	gw.mutex.Lock()
	gw.maxPoints = maxPoints
	gw.mutex.Unlock()
	return gw
}

// Start starts the data collection
func (gw *GraphWidget) Start() {
	gw.widgetMutex.Lock()
	if gw.started || gw.dataFunc == nil {
		gw.widgetMutex.Unlock()
		return
	}
	
	gw.started = true
	dataFunc := gw.dataFunc
	sampleInterval := gw.sampleInterval
	stopChan := gw.stopChan
	gw.widgetMutex.Unlock()
	
	// Add some initial test data to make the graph visible immediately
	for i := 0; i < 10; i++ {
		// Use AddDualPoint instead since there's no AddSecondaryPoint method
		gw.AddDualPoint(float64(i * 10), float64((10-i) * 5))
	}
	
	// Set initial max value
	gw.SetMaxValue(100)
	
	go func() {
		// Add an initial real data point immediately in the goroutine
		primary, secondary := dataFunc()
		gw.AddDualPoint(primary, secondary)
		
		ticker := time.NewTicker(sampleInterval)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				primary, secondary := dataFunc()
				gw.AddDualPoint(primary, secondary)
			case <-stopChan:
				return
			}
		}
	}()
}

// Stop stops the data collection
func (gw *GraphWidget) Stop() {
	gw.widgetMutex.Lock()
	defer gw.widgetMutex.Unlock()
	
	if !gw.started {
		return
	}
	
	if gw.stopChan != nil {
		close(gw.stopChan)
	}
	gw.started = false
	gw.stopChan = make(chan struct{})
}

// GraphWidgets returns the slice of GraphWidget pointers in the MultiGraph
func (mg *MultiGraph) GraphWidgets() []*GraphWidget {
    return mg.graphs
}

// DataPoints returns a copy of primary data points from the GraphWidget
func (gw *GraphWidget) DataPoints() []DataPoint {
    gw.mutex.RLock()
    defer gw.mutex.RUnlock()
    pts := make([]DataPoint, len(gw.data))
    copy(pts, gw.data)
    return pts
}

// SecondaryDataPoints returns a copy of secondary data points from the GraphWidget
func (gw *GraphWidget) SecondaryDataPoints() []DataPoint {
    gw.mutex.RLock()
    defer gw.mutex.RUnlock()
    pts := make([]DataPoint, len(gw.secondaryData))
    copy(pts, gw.secondaryData)
    return pts
}

// Labels returns the primary and secondary labels of the GraphWidget
func (gw *GraphWidget) Labels() (string, string) {
    gw.mutex.RLock()
    defer gw.mutex.RUnlock()
    return gw.primaryLabel, gw.secondaryLabel
}

// MultiGraph is a widget that displays multiple graphs
type MultiGraph struct {
	*tview.Box
	graphs     []*GraphWidget
	showTitle  bool
	title      string
	titleAlign int
}

// NewMultiGraph creates a new multi-graph widget
func NewMultiGraph() *MultiGraph {
	return &MultiGraph{
		Box:        tview.NewBox(),
		graphs:     make([]*GraphWidget, 0),
		showTitle:  true,
		titleAlign: tview.AlignCenter,
	}
}

// SetTitle sets the title of the multi-graph
func (mg *MultiGraph) SetTitle(title string) *MultiGraph {
	mg.title = title
	return mg
}

// SetTitleAlign sets the alignment of the title
func (mg *MultiGraph) SetTitleAlign(align int) *MultiGraph {
	mg.titleAlign = align
	return mg
}

// ShowTitle enables or disables the title
func (mg *MultiGraph) ShowTitle(show bool) *MultiGraph {
	mg.showTitle = show
	return mg
}

// AddGraph adds a graph to the multi-graph
func (mg *MultiGraph) AddGraph(graph *GraphWidget) *MultiGraph {
	mg.graphs = append(mg.graphs, graph)
	return mg
}

// SetGradientEnabled toggles static gradient shading for all graphs
func (mg *MultiGraph) SetGradientEnabled(enabled bool) *MultiGraph {
	for _, gw := range mg.graphs {
		gw.SetGradientEnabled(enabled)
	}
	return mg
}

// Draw draws the multi-graph
func (mg *MultiGraph) Draw(screen tcell.Screen) {
	mg.DrawForSubclass(screen, mg)
	
	x, y, width, height := mg.GetInnerRect()
	
	// Draw title if enabled
	titleHeight := 0
	if mg.showTitle && mg.title != "" {
		titleColor := tcell.ColorWhite
		if len(mg.graphs) > 0 {
			titleColor = mg.graphs[0].color
		}
		tview.Print(screen, mg.title, x, y, width, mg.titleAlign, titleColor)
		titleHeight = 1
	}
	
	// Calculate the height for each graph
	numGraphs := len(mg.graphs)
	if numGraphs == 0 {
		return
	}
	
	graphHeight := (height - titleHeight) / numGraphs
	if graphHeight < 5 {
		graphHeight = 5 // Minimum height for a graph
	}
	
	// Draw each graph
	for i, graph := range mg.graphs {
		if i*graphHeight+graphHeight+titleHeight > height {
			break // Don't draw graphs that don't fit
		}
		
		graphY := y + titleHeight + i*graphHeight
		
		// Set the position and size of the graph
		graph.SetRect(x, graphY, width, graphHeight)
		
		// Render the actual graph
		graph.Draw(screen)
	}
}
