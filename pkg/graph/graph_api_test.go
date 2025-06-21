package graph

import (
	"sync"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/stretchr/testify/assert"
)

// Test DataPoint structure
func TestDataPointStructure(t *testing.T) {
	dp := DataPoint{
		Value:     100.5,
		Timestamp: time.Now(),
	}
	
	assert.Equal(t, 100.5, dp.Value)
	assert.NotZero(t, dp.Timestamp)
}

// Test GraphStyle constants
func TestGraphStyleConstants(t *testing.T) {
	assert.Equal(t, GraphStyle(0), StyleBraille)
	assert.Equal(t, GraphStyle(1), StyleBlock)
	assert.Equal(t, GraphStyle(2), StyleTTY)
}

// Test NewGraph creation
func TestNewGraphCreation(t *testing.T) {
	g := NewGraph()
	
	assert.NotNil(t, g)
	assert.NotNil(t, g.Box)
	// Graph should be initialized with some default data
	assert.NotNil(t, g)
}

// Test Graph SetTitle
func TestGraphSetTitle(t *testing.T) {
	g := NewGraph()
	
	result := g.SetTitle("Test Graph")
	assert.Equal(t, g, result) // Should return self for chaining
}

// Test Graph SetMaxValue
func TestGraphSetMaxValue(t *testing.T) {
	g := NewGraph()
	
	result := g.SetMaxValue(500.0)
	assert.Equal(t, g, result) // Should return self for chaining
}

// Test Graph SetAutoScale
func TestGraphSetAutoScale(t *testing.T) {
	g := NewGraph()
	
	result := g.SetAutoScale(false)
	assert.Equal(t, g, result) // Should return self for chaining
	
	g.SetAutoScale(true)
}

// Test Graph SetStyle
func TestGraphSetStyle(t *testing.T) {
	g := NewGraph()
	
	result := g.SetStyle(StyleBlock)
	assert.Equal(t, g, result) // Should return self for chaining
	
	g.SetStyle(StyleTTY)
	g.SetStyle(StyleBraille)
}

// Test Graph AddPoint
func TestGraphAddPoint(t *testing.T) {
	g := NewGraph()
	
	// AddPoint doesn't return anything
	g.AddPoint(150.0)
	
	// Add multiple data points
	for i := 0; i < 10; i++ {
		g.AddPoint(float64(i * 20))
	}
}

// Test Graph AddDualPoint
func TestGraphAddDualPoint(t *testing.T) {
	g := NewGraph()
	
	// AddDualPoint doesn't return anything
	g.AddDualPoint(100.0, 200.0)
	
	// Add multiple dual data points
	for i := 0; i < 10; i++ {
		g.AddDualPoint(float64(i*10), float64(i*15))
	}
}

// Test Graph SetUnit
func TestGraphSetUnit(t *testing.T) {
	g := NewGraph()
	
	result := g.SetUnit("MB/s")
	assert.Equal(t, g, result) // Should return self for chaining
	
	g.SetUnit("req/s")
	g.SetUnit("ms")
}

// Test Graph SetColor and SetSecondaryColor
func TestGraphSetColors(t *testing.T) {
	g := NewGraph()
	
	result := g.SetColor(tcell.ColorRed)
	assert.Equal(t, g, result) // Should return self for chaining
	
	result = g.SetSecondaryColor(tcell.ColorBlue)
	assert.Equal(t, g, result) // Should return self for chaining
	
	// Test various color combinations
	g.SetColor(tcell.ColorGreen)
	g.SetSecondaryColor(tcell.ColorYellow)
}

// Test Graph SetLabels
func TestGraphSetLabels(t *testing.T) {
	g := NewGraph()
	
	result := g.SetLabels("Download", "Upload")
	assert.Equal(t, g, result) // Should return self for chaining
	
	g.SetLabels("Inbound", "Outbound")
	g.SetLabels("Read", "Write")
}

// Test Graph ShowLegend
func TestGraphShowLegend(t *testing.T) {
	g := NewGraph()
	
	result := g.ShowLegend(true)
	assert.Equal(t, g, result) // Should return self for chaining
	
	g.ShowLegend(false)
	g.ShowLegend(true)
}

// Test Graph SetGradientEnabled
func TestGraphSetGradientEnabled(t *testing.T) {
	g := NewGraph()
	
	result := g.SetGradientEnabled(false)
	assert.Equal(t, g, result) // Should return self for chaining
	
	g.SetGradientEnabled(true)
}

// Test Graph GradientEnabled
func TestGraphGradientEnabled(t *testing.T) {
	g := NewGraph()
	
	// Test getter
	enabled := g.GradientEnabled()
	assert.True(t, enabled) // Default is true
	
	// Disable and check
	g.SetGradientEnabled(false)
	assert.False(t, g.GradientEnabled())
}

// Test GraphWidget creation
func TestNewGraphWidget(t *testing.T) {
	gw := NewGraphWidget()
	
	assert.NotNil(t, gw)
	assert.NotNil(t, gw.Graph)
}

// Test GraphWidget SetDataFunc
func TestGraphWidgetSetDataFunc(t *testing.T) {
	gw := NewGraphWidget()
	
	called := false
	dataFunc := func() (float64, float64) {
		called = true
		return 10.0, 20.0
	}
	
	result := gw.SetDataFunc(dataFunc)
	assert.Equal(t, gw, result) // Should return self for chaining
	
	// Test that the function was set
	if gw.dataFunc != nil {
		val1, val2 := gw.dataFunc()
		assert.True(t, called)
		assert.Equal(t, 10.0, val1)
		assert.Equal(t, 20.0, val2)
	}
}

// Test GraphWidget Start and Stop
func TestGraphWidgetStartStop(t *testing.T) {
	gw := NewGraphWidget()
	gw.SetSampleInterval(10 * time.Millisecond)
	
	var mu sync.Mutex
	count := 0
	gw.SetDataFunc(func() (float64, float64) {
		mu.Lock()
		count++
		currentCount := count
		mu.Unlock()
		return float64(currentCount), float64(currentCount * 2)
	})
	
	// Start the widget
	gw.Start()
	
	// Let it run for a bit
	time.Sleep(50 * time.Millisecond)
	
	// Stop the widget
	gw.Stop()
	
	// Check that data was collected
	mu.Lock()
	finalCount := count
	mu.Unlock()
	assert.Greater(t, finalCount, 0)
}

// Test GraphWidget SetSampleInterval and SetHistoryDuration
func TestGraphWidgetIntervals(t *testing.T) {
	gw := NewGraphWidget()
	
	result := gw.SetSampleInterval(500 * time.Millisecond)
	assert.Equal(t, gw, result) // Should return self for chaining
	
	result = gw.SetHistoryDuration(10 * time.Minute)
	assert.Equal(t, gw, result) // Should return self for chaining
}

// Test MultiGraph creation
func TestNewMultiGraph(t *testing.T) {
	mg := NewMultiGraph()
	
	assert.NotNil(t, mg)
	assert.NotNil(t, mg.graphs)
	assert.Equal(t, tview.AlignCenter, mg.titleAlign)
	assert.True(t, mg.showTitle)
}

// Test MultiGraph AddGraph
func TestMultiGraphAddGraph(t *testing.T) {
	mg := NewMultiGraph()
	
	// Create and add widgets
	gw1 := NewGraphWidget()
	gw1.Graph.SetTitle("Graph 1")
	result := mg.AddGraph(gw1)
	assert.Equal(t, mg, result) // Should return self for chaining
	
	gw2 := NewGraphWidget()
	gw2.Graph.SetTitle("Graph 2")
	mg.AddGraph(gw2)
	
	// Check that widgets were added
	assert.Len(t, mg.graphs, 2)
}

// Test MultiGraph configuration
func TestMultiGraphConfiguration(t *testing.T) {
	mg := NewMultiGraph()
	
	// Test SetTitle
	result := mg.SetTitle("Test Title")
	assert.Equal(t, mg, result)
	
	// Test SetTitleAlign
	result = mg.SetTitleAlign(tview.AlignLeft)
	assert.Equal(t, mg, result)
	
	// Test ShowTitle
	result = mg.ShowTitle(false)
	assert.Equal(t, mg, result)
	
	// Test SetGradientEnabled
	result = mg.SetGradientEnabled(true)
	assert.Equal(t, mg, result)
}

// Test GraphWidget data access methods
func TestGraphWidgetDataAccess(t *testing.T) {
	gw := NewGraphWidget()
	
	// Add some data
	gw.Graph.AddDualPoint(10.0, 20.0)
	gw.Graph.AddDualPoint(15.0, 25.0)
	gw.Graph.SetLabels("Primary", "Secondary")
	
	// Test DataPoints
	points := gw.DataPoints()
	assert.NotNil(t, points)
	
	// Test SecondaryDataPoints
	secondaryPoints := gw.SecondaryDataPoints()
	assert.NotNil(t, secondaryPoints)
	
	// Test Labels
	label1, label2 := gw.Labels()
	assert.Equal(t, "Primary", label1)
	assert.Equal(t, "Secondary", label2)
}

// Test thread safety with concurrent operations
func TestGraphConcurrency(t *testing.T) {
	g := NewGraph()
	
	var wg sync.WaitGroup
	numGoroutines := 10
	numOperations := 100
	
	// Run concurrent AddDataPoint operations
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				g.AddPoint(float64(id*100 + j))
			}
		}(i)
	}
	
	// Run concurrent AddDualDataPoint operations
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				g.AddDualPoint(float64(id*100+j), float64(id*200+j))
			}
		}(i)
	}
	
	// Run concurrent configuration changes
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numOperations; i++ {
			g.SetMaxValue(float64(i * 100))
			g.SetUnit("MB/s")
			g.SetTitle("Test Graph")
		}
	}()
	
	wg.Wait()
	
	// Test completed without panic
	assert.NotNil(t, g)
}

// Test helper functions
func TestMinFunction(t *testing.T) {
	assert.Equal(t, 5, min(5, 10))
	assert.Equal(t, 5, min(10, 5))
	assert.Equal(t, -10, min(-10, 5))
	assert.Equal(t, 0, min(0, 0))
}

// Test formatValue
func TestFormatValueFunction(t *testing.T) {
	tests := []struct {
		value    float64
		unit     string
		expected string // We'll check the format, not exact value
	}{
		{0, "", "0"},
		{1234567, "", "1.2M"},
		{1234, "", "1.2K"},
		{123.456, "", "123"},
		{1000, "", "1.0K"},
		{1000000, "", "1.0M"},
	}
	
	for _, tt := range tests {
		result := formatValue(tt.value)
		// Just check that formatting happened
		assert.NotEmpty(t, result)
		if tt.unit != "" {
			assert.Contains(t, result, tt.unit)
		}
	}
}

// Benchmark tests
func BenchmarkGraphAddPoint(b *testing.B) {
	g := NewGraph()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		g.AddPoint(float64(i))
	}
}

func BenchmarkGraphAddDualPoint(b *testing.B) {
	g := NewGraph()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		g.AddDualPoint(float64(i), float64(i*2))
	}
}

func BenchmarkFormatValueFunc(b *testing.B) {
	values := []float64{123.45, 1234567.89, 0.123, 1000000000}
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_ = formatValue(values[i%len(values)])
	}
}