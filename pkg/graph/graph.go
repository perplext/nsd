package graph

import (
	"fmt"
	"math"
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
	}
	
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

// SetTitle sets the graph title
func (g *Graph) SetTitle(title string) *Graph {
	g.title = title
	return g
}

// SetColor sets the primary graph color
func (g *Graph) SetColor(color tcell.Color) *Graph {
	g.color = color
	return g
}

// SetSecondaryColor sets the secondary graph color
func (g *Graph) SetSecondaryColor(color tcell.Color) *Graph {
	g.secondaryColor = color
	return g
}

// SetMaxValue sets the maximum value for the y-axis
func (g *Graph) SetMaxValue(max float64) *Graph {
	g.maxValue = max
	g.autoScale = false
	return g
}

// SetAutoScale enables or disables auto-scaling
func (g *Graph) SetAutoScale(auto bool) *Graph {
	g.autoScale = auto
	return g
}

// SetUnit sets the unit for the y-axis
func (g *Graph) SetUnit(unit string) *Graph {
	g.unit = unit
	return g
}

// SetLabels sets the labels for the primary and secondary data
func (g *Graph) SetLabels(primary, secondary string) *Graph {
	g.primaryLabel = primary
	g.secondaryLabel = secondary
	return g
}

// ShowLegend enables or disables the legend
func (g *Graph) ShowLegend(show bool) *Graph {
	g.showLegend = show
	return g
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
	g.Box.DrawForSubclass(screen, g)

	g.mutex.RLock()
	defer g.mutex.RUnlock()

	// Get the graph area
	x, y, width, height := g.GetInnerRect()
	if width <= 2 || height <= 2 {
		return
	}
	
	// Draw a background grid for better visibility
	for i := 0; i < width; i++ {
		for j := 0; j < height; j++ {
			if j % 2 == 0 && i % 5 == 0 {
				screen.SetContent(x+i, y+j, '.', nil, tcell.StyleDefault.Foreground(tcell.ColorGray))
			}
		}
	}
	
	// Print debug info
	debugInfo := fmt.Sprintf("Graph size: %dx%d, Data points: %d", width, height, len(g.data))
	tview.Print(screen, debugInfo, x, y, width, tview.AlignLeft, g.color)

	// Draw title
	if g.title != "" {
		titleX := x + (width-len(g.title))/2
		for i, r := range g.title {
			screen.SetContent(titleX+i, y, r, nil, tcell.StyleDefault.Foreground(g.color))
		}
	}

	// Calculate the graph area
	graphY := y + 1
	graphHeight := height - 2
	if g.showLegend {
		graphHeight--
	}
	
	if graphHeight <= 0 {
		return
	}

	// Draw y-axis labels
	maxLabel := formatValue(g.maxValue) + g.unit
	midLabel := formatValue(g.maxValue/2) + g.unit
	
	for i, r := range maxLabel {
		if x+i < x+width {
			screen.SetContent(x+i, graphY, r, nil, tcell.StyleDefault.Foreground(tcell.ColorGray))
		}
	}
	
	for i, r := range midLabel {
		if x+i < x+width {
			screen.SetContent(x+i, graphY+graphHeight/2, r, nil, tcell.StyleDefault.Foreground(tcell.ColorGray))
		}
	}
	
	// Draw zero label
	zeroLabel := "0" + g.unit
	for i, r := range zeroLabel {
		if x+i < x+width {
			screen.SetContent(x+i, graphY+graphHeight-1, r, nil, tcell.StyleDefault.Foreground(tcell.ColorGray))
		}
	}

	// Draw the graph
	dataLen := len(g.data)
	secondaryDataLen := len(g.secondaryData)
	
	if dataLen == 0 {
		return
	}

	// Determine available columns for plotting (excluding axes)
	colsAvailable := width - 2
	if colsAvailable <= 0 {
		return
	}
	// Draw the primary graph, sampling points across full width
	for i := 0; i < colsAvailable; i++ {
		// Map column to data index
		var value float64
		if dataLen == 0 {
			continue
		} else if dataLen == 1 {
			value = g.data[0].Value
		} else {
			f := float64(i) / float64(colsAvailable-1) * float64(dataLen-1)
			idx := int(math.Round(f))
			if idx < 0 {
				idx = 0
			}
			if idx >= dataLen {
				idx = dataLen - 1
			}
			value = g.data[idx].Value
		}
		// Scale the value to the graph height
		scaledValue := int(math.Floor((value / g.maxValue) * float64(graphHeight-1)))
		scaledValue = min(scaledValue, graphHeight-1)
		
		// Shaded bar: draw primary and secondary shading
		primaryScaled := scaledValue
		secondaryScaled := 0
		if secondaryDataLen > 0 {
			var secValue float64
			if secondaryDataLen == 1 {
				secValue = g.secondaryData[0].Value
			} else {
				f2 := float64(i) / float64(colsAvailable-1) * float64(secondaryDataLen-1)
				idx2 := int(math.Round(f2))
				if idx2 < 0 {
					idx2 = 0
				}
				if idx2 >= secondaryDataLen {
					idx2 = secondaryDataLen - 1
				}
				secValue = g.secondaryData[idx2].Value
			}
			secondaryScaled = int(math.Floor((secValue / g.maxValue) * float64(graphHeight-1)))
			secondaryScaled = min(secondaryScaled, graphHeight-1)
		}
		maxScaled := primaryScaled
		if secondaryScaled > maxScaled {
			maxScaled = secondaryScaled
		}
		for j := 0; j < graphHeight; j++ {
			row := graphY + graphHeight - 1 - j
			if j > maxScaled {
				screen.SetContent(x+i+1, row, ' ', nil, tcell.StyleDefault)
				continue
			}
			rowRatio := float64(j) / float64(graphHeight-1)
			ch := shadeBlock(rowRatio)
			var style tcell.Style
			if j <= primaryScaled {
				style = tcell.StyleDefault.Foreground(g.color)
			} else {
				style = tcell.StyleDefault.Foreground(g.secondaryColor)
			}
			screen.SetContent(x+i+1, row, ch, nil, style)
		}
	}
	
	// Draw the secondary graph if available, sampling similarly
	if secondaryDataLen > 0 {
		for i := 0; i < colsAvailable; i++ {
			// Map column to secondary data index
			var value float64
			if secondaryDataLen == 1 {
				value = g.secondaryData[0].Value
			} else {
				f := float64(i) / float64(colsAvailable-1) * float64(secondaryDataLen-1)
				idx := int(math.Round(f))
				if idx < 0 {
					idx = 0
				}
				if idx >= secondaryDataLen {
					idx = secondaryDataLen - 1
				}
				value = g.secondaryData[idx].Value
			}
			// Scale the value to the graph height
			scaledValue := int(math.Floor((value / g.maxValue) * float64(graphHeight-1)))
			scaledValue = min(scaledValue, graphHeight-1)
			
			// Draw the point with a more visible character
			pointY := graphY + graphHeight - 1 - scaledValue
			screen.SetContent(x+i+1, pointY, '*', nil, tcell.StyleDefault.Foreground(g.secondaryColor))
			
			// Add a small line below the point for better visibility
			for j := 1; j <= min(2, scaledValue); j++ {
				if pointY+j < graphY+graphHeight {
					screen.SetContent(x+i+1, pointY+j, '.', nil, tcell.StyleDefault.Foreground(g.secondaryColor))
				}
			}
		}
	}
	
	// Draw legend if enabled
	if g.showLegend {
		legendY := graphY + graphHeight
		legendText := fmt.Sprintf("[%s]%s[%s] [%s]%s[%s]", 
			ColorToHex(g.color), g.primaryLabel, ColorToHex(tcell.ColorWhite),
			ColorToHex(g.secondaryColor), g.secondaryLabel, ColorToHex(tcell.ColorWhite))
		
		tview.Print(screen, legendText, x, legendY, width, tview.AlignLeft, tcell.ColorWhite)
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
	gw.dataFunc = f
	return gw
}

// SetSampleInterval sets how often to sample data
func (gw *GraphWidget) SetSampleInterval(d time.Duration) *GraphWidget {
	gw.sampleInterval = d
	return gw
}

// SetHistoryDuration sets how much history to keep
func (gw *GraphWidget) SetHistoryDuration(d time.Duration) *GraphWidget {
	gw.historyDuration = d
	maxPoints := int(d / gw.sampleInterval)
	gw.Graph.maxPoints = maxPoints
	return gw
}

// Start starts the data collection
func (gw *GraphWidget) Start() {
	if gw.started || gw.dataFunc == nil {
		return
	}
	
	gw.started = true
	
	// Add some initial test data to make the graph visible immediately
	for i := 0; i < 10; i++ {
		// Use AddDualPoint instead since there's no AddSecondaryPoint method
		gw.AddDualPoint(float64(i * 10), float64((10-i) * 5))
	}
	
	// Set initial max value
	gw.maxValue = 100
	
	go func() {
		// Add an initial real data point immediately in the goroutine
		primary, secondary := gw.dataFunc()
		gw.AddDualPoint(primary, secondary)
		
		ticker := time.NewTicker(gw.sampleInterval)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				primary, secondary := gw.dataFunc()
				gw.AddDualPoint(primary, secondary)
			case <-gw.stopChan:
				return
			}
		}
	}()
}

// Stop stops the data collection
func (gw *GraphWidget) Stop() {
	if !gw.started {
		return
	}
	
	close(gw.stopChan)
	gw.started = false
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

// Draw draws the multi-graph
func (mg *MultiGraph) Draw(screen tcell.Screen) {
	mg.Box.DrawForSubclass(screen, mg)
	
	x, y, width, height := mg.GetInnerRect()
	
	// Draw debug info
	debugInfo := fmt.Sprintf("MultiGraph: %dx%d, Graphs: %d", width, height, len(mg.graphs))
	if len(mg.graphs) > 0 {
		tview.Print(screen, debugInfo, x, y, width, tview.AlignLeft, mg.graphs[0].color)
	} else {
		tview.Print(screen, debugInfo, x, y, width, tview.AlignLeft, tcell.ColorGray)
	}
	
	// Draw title if enabled
	titleHeight := 1 // Always reserve space for debug info or title
	if mg.showTitle && mg.title != "" {
		if len(mg.graphs) > 0 {
			tview.Print(screen, mg.title, x, y+1, width, mg.titleAlign, mg.graphs[0].color)
		} else {
			tview.Print(screen, mg.title, x, y+1, width, mg.titleAlign, tcell.ColorGray)
		}
		titleHeight = 2
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
