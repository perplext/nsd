package graph

import (
	"fmt"
	"math"
	"math/rand"
	"testing"
	"time"
	"unsafe"
	
	"github.com/gdamore/tcell/v2"
)

// BenchmarkGraphDataOperations benchmarks data operations
func BenchmarkGraphDataOperations(b *testing.B) {
	b.Run("AddDataPoint", func(b *testing.B) {
		g := NewGraph()
		g.maxPoints = 1000
		
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			g.AddDataPoint(float64(i), float64(i)*1.5)
		}
		
		b.ReportMetric(float64(len(g.data)), "datapoints")
	})
	
	b.Run("AddDataPointWithRotation", func(b *testing.B) {
		g := NewGraph()
		g.maxPoints = 100 // Force rotation
		
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			g.AddDataPoint(float64(i), float64(i)*1.5)
		}
	})
	
	b.Run("ClearData", func(b *testing.B) {
		g := NewGraph()
		
		// Pre-populate
		for i := 0; i < 1000; i++ {
			g.AddDataPoint(float64(i), float64(i)*1.5)
		}
		
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			g.ClearData()
			// Re-populate for next iteration
			for j := 0; j < 1000; j++ {
				g.AddDataPoint(float64(j), float64(j)*1.5)
			}
		}
	})
}

// BenchmarkGraphRendering benchmarks different rendering styles
func BenchmarkGraphRendering(b *testing.B) {
	styles := []string{"braille", "block", "tty"}
	dataSizes := []int{10, 100, 1000}
	screenSizes := []struct {
		width, height int
		name          string
	}{
		{80, 24, "Small"},
		{120, 40, "Medium"},
		{200, 60, "Large"},
	}
	
	for _, style := range styles {
		for _, dataSize := range dataSizes {
			for _, screenSize := range screenSizes {
				b.Run(fmt.Sprintf("%s-%dpts-%s", style, dataSize, screenSize.name), 
					func(b *testing.B) {
					screen := NewMockScreen(screenSize.width, screenSize.height)
					g := NewGraph()
					g.SetStyle(style)
					
					// Add data
					for i := 0; i < dataSize; i++ {
						y := math.Sin(float64(i)*0.1) * 50 + 50
						g.AddDataPoint(y, y*0.8)
					}
					
					b.ResetTimer()
					b.ReportAllocs()
					
					for i := 0; i < b.N; i++ {
						g.DrawInBounds(screen, 0, 0, screenSize.width, screenSize.height)
					}
				})
			}
		}
	}
}

// BenchmarkBrailleGeneration benchmarks Braille character generation
func BenchmarkBrailleGeneration(b *testing.B) {
	patterns := [][]bool{
		{true, false, true, false, true, false, true, false},
		{false, true, false, true, false, true, false, true},
		{true, true, true, true, false, false, false, false},
		{false, false, false, false, true, true, true, true},
	}
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		pattern := patterns[i%len(patterns)]
		_ = getBrailleChar(
			pattern[0], pattern[1], pattern[2], pattern[3],
			pattern[4], pattern[5], pattern[6], pattern[7],
		)
	}
}

// BenchmarkInterpolation benchmarks value interpolation
func BenchmarkInterpolation(b *testing.B) {
	g := NewGraph()
	
	// Add sparse data
	for i := 0; i < 100; i += 10 {
		g.AddDataPoint(float64(i), float64(i)*2)
	}
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		x := float64(i % 100)
		_ = g.interpolateValue(x, true)
		_ = g.interpolateValue(x, false)
	}
}

// BenchmarkScaling benchmarks value scaling operations
func BenchmarkScaling(b *testing.B) {
	g := NewGraph()
	g.minValue = 0
	g.maxValue = 1000
	
	values := make([]float64, 1000)
	for i := range values {
		values[i] = rand.Float64() * 1000
	}
	
	b.Run("Linear", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			val := values[i%len(values)]
			scaled := (val - g.minValue) / (g.maxValue - g.minValue)
			_ = scaled
		}
	})
	
	b.Run("WithBounds", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			val := values[i%len(values)]
			if val < g.minValue {
				val = g.minValue
			} else if val > g.maxValue {
				val = g.maxValue
			}
			scaled := (val - g.minValue) / (g.maxValue - g.minValue)
			_ = scaled
		}
	})
}

// BenchmarkMultiGraph benchmarks multi-graph operations
func BenchmarkMultiGraph(b *testing.B) {
	graphCounts := []int{2, 4, 8}
	
	for _, count := range graphCounts {
		b.Run(fmt.Sprintf("Graphs-%d", count), func(b *testing.B) {
			mg := NewMultiGraph()
			
			// Add graphs
			for i := 0; i < count; i++ {
				g := NewGraph()
				g.SetTitle(fmt.Sprintf("Graph %d", i))
				mg.AddGraph(fmt.Sprintf("graph%d", i), g)
			}
			
			// Add data to all graphs
			for i := 0; i < 100; i++ {
				for j := 0; j < count; j++ {
					if g := mg.GetGraph(fmt.Sprintf("graph%d", j)); g != nil {
						g.AddDataPoint(float64(i), float64(i*j))
					}
				}
			}
			
			screen := NewMockScreen(200, 60)
			
			b.ResetTimer()
			b.ReportAllocs()
			
			for i := 0; i < b.N; i++ {
				mg.Draw(screen)
			}
		})
	}
}

// BenchmarkHistoricalData benchmarks operations with historical data
func BenchmarkHistoricalData(b *testing.B) {
	timeRanges := []time.Duration{
		time.Minute,
		time.Hour,
		24 * time.Hour,
	}
	
	for _, timeRange := range timeRanges {
		b.Run(timeRange.String(), func(b *testing.B) {
			g := NewGraph()
			g.EnableTimeAxis(true)
			
			// Generate historical data
			now := time.Now()
			dataPoints := int(timeRange.Seconds())
			if dataPoints > 3600 {
				dataPoints = 3600 // Cap at 1 hour of second-resolution data
			}
			
			for i := 0; i < dataPoints; i++ {
				ts := now.Add(-time.Duration(i) * time.Second)
				dp := DataPoint{
					Timestamp: ts,
					Value:     rand.Float64() * 100,
				}
				g.data = append(g.data, dp)
			}
			
			b.ResetTimer()
			b.ReportAllocs()
			
			screen := NewMockScreen(120, 40)
			for i := 0; i < b.N; i++ {
				g.DrawInBounds(screen, 0, 0, 120, 40)
			}
			
			b.ReportMetric(float64(len(g.data)), "datapoints")
		})
	}
}

// BenchmarkColorGradient benchmarks gradient color calculations
func BenchmarkColorGradient(b *testing.B) {
	g := NewGraph()
	g.SetGradient(true)
	g.gradientStart = tcell.ColorGreen
	g.gradientEnd = tcell.ColorRed
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		factor := float64(i%100) / 100.0
		_ = g.interpolateColor(factor)
	}
}

// BenchmarkConcurrentDataAccess benchmarks concurrent graph access
func BenchmarkConcurrentDataAccess(b *testing.B) {
	g := NewGraph()
	
	// Pre-populate
	for i := 0; i < 1000; i++ {
		g.AddDataPoint(float64(i), float64(i)*1.5)
	}
	
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			switch i % 3 {
			case 0:
				// Add data
				g.AddDataPoint(float64(i), float64(i)*1.5)
			case 1:
				// Read data
				pts := g.DataPoints()
				_ = len(pts)
			case 2:
				// Draw
				screen := NewMockScreen(80, 24)
				g.DrawInBounds(screen, 0, 0, 80, 24)
			}
			i++
		}
	})
}

// BenchmarkMemoryUsage benchmarks memory usage patterns
func BenchmarkMemoryUsage(b *testing.B) {
	b.Run("DataPointAllocation", func(b *testing.B) {
		b.ReportAllocs()
		
		var totalSize int64
		for i := 0; i < b.N; i++ {
			dp := DataPoint{
				Timestamp: time.Now(),
				Value:     float64(i),
			}
			totalSize += int64(unsafe.Sizeof(dp))
		}
		
		b.ReportMetric(float64(totalSize)/float64(b.N), "bytes/point")
	})
	
	b.Run("GraphWithData", func(b *testing.B) {
		graphs := make([]*Graph, b.N)
		
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			g := NewGraph()
			// Add typical amount of data
			for j := 0; j < 1000; j++ {
				g.AddDataPoint(float64(j), float64(j)*1.5)
			}
			graphs[i] = g
		}
		
		// Prevent optimization
		if len(graphs) != b.N {
			b.Fatal("graphs optimized away")
		}
	})
}