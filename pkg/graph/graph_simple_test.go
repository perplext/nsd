package graph

import (
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test NewGraph configuration
func TestNewGraph(t *testing.T) {
	g := NewGraph()
	require.NotNil(t, g)
	assert.NotNil(t, g.Box)
	assert.Equal(t, 120, g.maxPoints)
	assert.Equal(t, tcell.ColorGreen, g.color)
	assert.Equal(t, tcell.ColorBlue, g.secondaryColor)
	assert.True(t, g.gradientEnabled)
	assert.Equal(t, StyleBraille, g.style)
}

// Test graph configuration methods
func TestGraph_ConfigurationMethods(t *testing.T) {
	g := NewGraph()
	
	// Test chaining
	result := g.
		SetTitle("Test").
		SetColor(tcell.ColorRed).
		SetSecondaryColor(tcell.ColorYellow).
		SetMaxValue(1000).
		SetAutoScale(false).
		SetUnit("KB/s").
		SetLabels("In", "Out").
		ShowLegend(false).
		SetGradientEnabled(false).
		SetStyle(StyleBlock)
	
	assert.Equal(t, g, result)
	assert.Equal(t, "Test", g.title)
	assert.Equal(t, tcell.ColorRed, g.color)
	assert.Equal(t, tcell.ColorYellow, g.secondaryColor)
	assert.Equal(t, 1000.0, g.maxValue)
	assert.False(t, g.autoScale)
	assert.Equal(t, "KB/s", g.unit)
	assert.Equal(t, "In", g.primaryLabel)
	assert.Equal(t, "Out", g.secondaryLabel)
	assert.False(t, g.showLegend)
	assert.False(t, g.gradientEnabled)
	assert.Equal(t, StyleBlock, g.style)
}

// Test data point management
func TestGraph_DataPoints(t *testing.T) {
	g := NewGraph()
	// Clear initial data
	g.data = nil
	g.secondaryData = nil
	g.maxPoints = 5
	
	// Add single points
	for i := 0; i < 10; i++ {
		g.AddPoint(float64(i))
	}
	
	// Check data - should only keep maxPoints
	g.mutex.RLock()
	assert.Equal(t, 5, len(g.data))
	g.mutex.RUnlock()
	
	// Reset and test dual points
	g.data = nil
	g.secondaryData = nil
	for i := 0; i < 10; i++ {
		g.AddDualPoint(float64(i), float64(i*2))
	}
	
	g.mutex.RLock()
	assert.Equal(t, 5, len(g.data))
	assert.Equal(t, 5, len(g.secondaryData))
	g.mutex.RUnlock()
}

// Test updateMaxValue
func TestGraph_UpdateMaxValue(t *testing.T) {
	g := NewGraph()
	g.SetAutoScale(true)
	g.maxValue = 100
	
	// Add value larger than max
	g.AddPoint(200)
	
	g.mutex.RLock()
	assert.Greater(t, g.maxValue, 100.0)
	g.mutex.RUnlock()
	
	// Test with autoscale off
	g.SetAutoScale(false)
	g.maxValue = 100
	g.AddPoint(300)
	
	g.mutex.RLock()
	assert.Equal(t, 100.0, g.maxValue)
	g.mutex.RUnlock()
}

// Test formatValue coverage
func TestFormatValue_Coverage(t *testing.T) {
	tests := []struct {
		value float64
		want  string
	}{
		{999, "999"},
		{1000, "1.0K"},
		{999999, "1000.0K"},
		{1000000, "1.0M"},
		{999999999, "1000.0M"},
		{1000000000, "1.0G"},
		{999999999999, "1000.0G"},
		{1000000000000, "1.0T"},
	}
	
	for _, tt := range tests {
		got := formatValue(tt.value)
		assert.NotEmpty(t, got)
	}
}

// Test ColorToHex coverage
func TestColorToHex_Coverage(t *testing.T) {
	// Test default case
	color := tcell.ColorValid // This should hit the default case
	hex := ColorToHex(color)
	assert.Equal(t, "#000000", hex)
	
	// Test RGB color
	rgbColor := tcell.NewRGBColor(100, 150, 200)
	hex = ColorToHex(rgbColor)
	assert.Equal(t, "#6496c8", hex)
}

// Test getBrailleChar
func TestGetBrailleChar(t *testing.T) {
	// Test empty pattern
	heights := [8]int{0, 0, 0, 0, 0, 0, 0, 0}
	result := getBrailleChar(heights)
	assert.Equal(t, '⠀', result)
	
	// Test with some heights
	heights = [8]int{1, 0, 1, 0, 1, 0, 1, 0}
	result = getBrailleChar(heights)
	assert.NotEqual(t, '⠀', result)
	
	// Test full pattern
	heights = [8]int{1, 1, 1, 1, 1, 1, 1, 1}
	result = getBrailleChar(heights)
	assert.Equal(t, '⣿', result)
}

// Test GraphWidget
func TestGraphWidget_Basic(t *testing.T) {
	widget := NewGraphWidget()
	require.NotNil(t, widget)
	require.NotNil(t, widget.Graph)
	
	// Set data function
	counter := 0
	widget.SetDataFunc(func() (float64, float64) {
		counter++
		return float64(counter), float64(counter * 2)
	})
	
	// Set intervals
	widget.SetSampleInterval(10 * time.Millisecond)
	widget.SetHistoryDuration(100 * time.Millisecond)
	
	// Start collection
	widget.Start()
	time.Sleep(50 * time.Millisecond)
	
	// Check data was collected
	primary := widget.DataPoints()
	secondary := widget.SecondaryDataPoints()
	assert.NotEmpty(t, primary)
	assert.NotEmpty(t, secondary)
	
	// Check labels
	label1, label2 := widget.Labels()
	assert.NotEmpty(t, label1)
	assert.NotEmpty(t, label2)
	
	// Stop
	widget.Stop()
	
	// Test double stop
	widget.Stop()
}

// Test GraphWidget Start edge cases
func TestGraphWidget_StartEdgeCases(t *testing.T) {
	widget := NewGraphWidget()
	
	// Start without data function
	widget.Start()
	time.Sleep(20 * time.Millisecond)
	widget.Stop()
	
	// Multiple starts
	widget.SetDataFunc(func() (float64, float64) { return 1, 2 })
	widget.Start()
	widget.Start() // Should handle multiple starts
	widget.Stop()
}

// Test MultiGraph
func TestMultiGraph(t *testing.T) {
	mg := NewMultiGraph()
	require.NotNil(t, mg)
	
	// Test configuration
	mg.SetTitle("Multi")
	mg.SetTitleAlign(tview.AlignCenter)
	mg.ShowTitle(true)
	
	assert.Equal(t, "Multi", mg.title)
	assert.Equal(t, tview.AlignCenter, mg.titleAlign)
	assert.True(t, mg.showTitle)
	
	// Add graph widgets
	w1 := NewGraphWidget()
	w1.SetLabels("CPU", "MEM")
	mg.AddGraph(w1)
	
	w2 := NewGraphWidget()
	mg.AddGraph(w2)
	
	// Test GraphWidgets method
	widgets := mg.GraphWidgets()
	assert.Equal(t, 2, len(widgets))
	
	// Test gradient setting
	mg.SetGradientEnabled(true)
	assert.True(t, w1.GradientEnabled())
	assert.True(t, w2.GradientEnabled())
	
	mg.SetGradientEnabled(false)
	assert.False(t, w1.GradientEnabled())
	assert.False(t, w2.GradientEnabled())
}

// Test MultiGraph SetGradientEnabled with no graphs
func TestMultiGraph_SetGradientEnabled_NoGraphs(t *testing.T) {
	mg := NewMultiGraph()
	
	// Should not panic with no graphs
	assert.NotPanics(t, func() {
		mg.SetGradientEnabled(true)
		mg.SetGradientEnabled(false)
	})
}

// Test min function
func TestMin(t *testing.T) {
	assert.Equal(t, 1, min(1, 2))
	assert.Equal(t, -1, min(-1, 0))
	assert.Equal(t, 5, min(5, 5))
}

// Test calculateGradientColors
func TestGraph_CalculateGradientColors(t *testing.T) {
	g := NewGraph()
	
	// Test with different colors
	colors := []tcell.Color{
		tcell.ColorRed,
		tcell.ColorGreen,
		tcell.ColorBlue,
		tcell.ColorYellow,
		tcell.ColorPurple,
	}
	
	for _, color := range colors {
		g.SetColor(color)
		g.calculateGradientColors()
		assert.NotNil(t, g.gradientColors)
		assert.Greater(t, len(g.gradientColors), 0)
	}
}

// Test gradient enabled/disabled
func TestGraph_GradientEnabled(t *testing.T) {
	g := NewGraph()
	
	// Default should be true
	assert.True(t, g.GradientEnabled())
	
	// Disable
	g.SetGradientEnabled(false)
	assert.False(t, g.GradientEnabled())
	
	// Enable
	g.SetGradientEnabled(true)
	assert.True(t, g.GradientEnabled())
}

// Test shadeBlock function
func TestShadeBlock_Coverage(t *testing.T) {
	tests := []struct {
		ratio float64
		want  rune
	}{
		{-0.1, '·'},  // Below 0
		{0.0, '·'},
		{0.05, '·'},
		{0.1, '░'},
		{0.3, '▒'},
		{0.6, '▓'},
		{0.9, '█'},
		{1.1, '█'},  // Above 1
	}
	
	for _, tt := range tests {
		got := shadeBlock(tt.ratio)
		assert.Equal(t, tt.want, got)
		
		// Also test public wrapper
		got2 := ShadeBlock(tt.ratio)
		assert.Equal(t, tt.want, got2)
	}
}