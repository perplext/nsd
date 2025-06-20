package ui

import (
	"fmt"
	"net"
	"testing"
	"time"
	
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/perplext/nsd/pkg/graph"
	"github.com/perplext/nsd/pkg/netcap"
)

// MockScreen implements tcell.Screen for benchmarking
type MockScreen struct {
	width, height int
	cells         [][]rune
	styles        [][]tcell.Style
}

func NewMockScreen(width, height int) *MockScreen {
	ms := &MockScreen{
		width:  width,
		height: height,
		cells:  make([][]rune, height),
		styles: make([][]tcell.Style, height),
	}
	for i := range ms.cells {
		ms.cells[i] = make([]rune, width)
		ms.styles[i] = make([]tcell.Style, width)
	}
	return ms
}

func (ms *MockScreen) Init() error                                       { return nil }
func (ms *MockScreen) Fini()                                            {}
func (ms *MockScreen) Clear()                                           {}
func (ms *MockScreen) Fill(rune, tcell.Style)                          {}
func (ms *MockScreen) SetCell(x, y int, style tcell.Style, ch ...rune) {}
func (ms *MockScreen) GetContent(x, y int) (mainc rune, combc []rune, style tcell.Style, width int) {
	return ' ', nil, tcell.StyleDefault, 1
}
func (ms *MockScreen) SetContent(x, y int, mainc rune, combc []rune, style tcell.Style) {
	if x >= 0 && x < ms.width && y >= 0 && y < ms.height {
		ms.cells[y][x] = mainc
		ms.styles[y][x] = style
	}
}
func (ms *MockScreen) SetStyle(tcell.Style)                {}
func (ms *MockScreen) ShowCursor(int, int)                 {}
func (ms *MockScreen) HideCursor()                         {}
func (ms *MockScreen) Size() (int, int)                    { return ms.width, ms.height }
func (ms *MockScreen) ChannelEvents(ch chan<- tcell.Event, quit <-chan struct{}) {}
func (ms *MockScreen) PollEvent() tcell.Event              { return nil }
func (ms *MockScreen) HasPendingEvent() bool               { return false }
func (ms *MockScreen) PostEvent(tcell.Event) error         { return nil }
func (ms *MockScreen) PostEventWait(tcell.Event)           {}
func (ms *MockScreen) EnableMouse(...tcell.MouseFlags)     {}
func (ms *MockScreen) EnablePaste()                        {}
func (ms *MockScreen) DisableMouse()                       {}
func (ms *MockScreen) DisablePaste()                       {}
func (ms *MockScreen) HasMouse() bool                      { return false }
func (ms *MockScreen) Colors() int                         { return 256 }
func (ms *MockScreen) Show()                               {}
func (ms *MockScreen) Sync()                               {}
func (ms *MockScreen) CharacterSet() string                { return "UTF-8" }
func (ms *MockScreen) RegisterRuneFallback(rune, string)   {}
func (ms *MockScreen) UnregisterRuneFallback(rune)         {}
func (ms *MockScreen) CanDisplay(rune, bool) bool          { return true }
func (ms *MockScreen) Resize(int, int, int, int)           {}
func (ms *MockScreen) SetSize(int, int)                    {}
func (ms *MockScreen) Suspend() error                      { return nil }
func (ms *MockScreen) Resume() error                       { return nil }
func (ms *MockScreen) Beep() error                         { return nil }
func (ms *MockScreen) DisableFocus()                       {}
func (ms *MockScreen) EnableFocus()                        {}
func (ms *MockScreen) GetClipboard()                       {}
func (ms *MockScreen) HasKey(tcell.Key) bool               { return true }
func (ms *MockScreen) LockRegion(x, y, width, height int, lock bool) {}
func (ms *MockScreen) Tty() (tcell.Tty, bool)              { return nil, false }
func (ms *MockScreen) SetClipboard([]byte)                 {}
func (ms *MockScreen) SetCursorStyle(tcell.CursorStyle, ...tcell.Color) {}
func (ms *MockScreen) SetTitle(string)                     {}

// BenchmarkGraphRendering benchmarks graph rendering performance
func BenchmarkGraphRendering(b *testing.B) {
	styles := []struct {
		style graph.GraphStyle
		name  string
	}{
		{graph.StyleBraille, "Braille"},
		{graph.StyleBlock, "Block"},
		{graph.StyleTTY, "TTY"},
	}
	sizes := []struct {
		width, height int
		name          string
	}{
		{80, 24, "Small"},
		{120, 40, "Medium"},
		{200, 60, "Large"},
	}
	
	for _, styleInfo := range styles {
		for _, size := range sizes {
			b.Run(fmt.Sprintf("%s-%s", styleInfo.name, size.name), func(b *testing.B) {
				screen := NewMockScreen(size.width, size.height)
				g := graph.NewGraph()
				g.SetStyle(styleInfo.style)
				
				// Add test data
				for i := 0; i < 100; i++ {
					g.AddPoint(float64(i*10))
				}
				
				b.ResetTimer()
				b.ReportAllocs()
				
				for i := 0; i < b.N; i++ {
					g.Draw(screen)
				}
			})
		}
	}
}

// BenchmarkVisualizationUpdate benchmarks visualization update performance
func BenchmarkVisualizationUpdate(b *testing.B) {
	visualizations := []struct {
		name    string
		factory func() Visualization
	}{
		{"Matrix", NewMatrixRainVisualization},
		{"Heatmap", NewHeatmapVisualization},
		{"Speedometer", NewSpeedometerVisualization},
		{"Sankey", NewSankeyVisualization},
		{"Radial", NewRadialConnectionVisualization},
	}
	
	monitor := netcap.NewNetworkMonitor()
	
	// Add test connections
	for i := 0; i < 100; i++ {
		conn := &netcap.Connection{
			SrcIP:    net.ParseIP(fmt.Sprintf("192.168.1.%d", i%256)),
			DstIP:    net.ParseIP(fmt.Sprintf("10.0.0.%d", i%256)),
			SrcPort:  uint16(1000 + i),
			DstPort:  uint16(80),
			Protocol: "TCP",
			Service:  "HTTP",
			Size:     uint64(i * 1000),
			Packets:  uint64(i * 10),
			LastSeen: time.Now(),
		}
		key := netcap.ConnectionKey{
			SrcIP:    conn.SrcIP.String(),
			DstIP:    conn.DstIP.String(),
			SrcPort:  conn.SrcPort,
			DstPort:  conn.DstPort,
			Protocol: conn.Protocol,
		}
		monitor.Interfaces["test0"] = &netcap.InterfaceStats{
			Name:        "test0",
			Connections: map[netcap.ConnectionKey]*netcap.Connection{key: conn},
		}
	}
	
	for _, viz := range visualizations {
		b.Run(viz.name, func(b *testing.B) {
			v := viz.factory()
			
			b.ResetTimer()
			b.ReportAllocs()
			
			for i := 0; i < b.N; i++ {
				v.Update(monitor)
			}
		})
	}
}

// BenchmarkThemeOperations benchmarks theme operations
func BenchmarkThemeOperations(b *testing.B) {
	b.Run("GetUsageColor", func(b *testing.B) {
		values := []float64{0.1, 0.3, 0.5, 0.7, 0.9, 1.1}
		
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			_ = GetUsageColor(values[i%len(values)])
		}
	})
	
	b.Run("InterpolateColor", func(b *testing.B) {
		c1 := tcell.ColorRed
		c2 := tcell.ColorGreen
		
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			_ = interpolateColor(c1, c2, float64(i%100)/100.0)
		}
	})
	
	b.Run("ParseHex", func(b *testing.B) {
		colors := []string{"#ff0000", "#00ff00", "#0000ff", "#ffffff", "#000000"}
		
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			_ = parseHex(colors[i%len(colors)])
		}
	})
}

// BenchmarkAnimations benchmarks animation calculations
func BenchmarkAnimations(b *testing.B) {
	animations := []string{"Rainbow", "Pulse", "Fire", "Matrix", "Wave", "Sparkle"}
	baseColor := tcell.ColorWhite
	
	for _, anim := range animations {
		b.Run(anim, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			
			for i := 0; i < b.N; i++ {
				_ = GetAnimatedBorderColor(baseColor, anim, i%100)
			}
		})
	}
}

// BenchmarkConnectionTable benchmarks connection table rendering
func BenchmarkConnectionTable(b *testing.B) {
	connectionCounts := []int{10, 100, 1000}
	
	for _, count := range connectionCounts {
		b.Run(fmt.Sprintf("Connections-%d", count), func(b *testing.B) {
			table := tview.NewTable()
			
			// Add header
			headers := []string{"Source", "Destination", "Protocol", "Bytes In", "Bytes Out"}
			for i, header := range headers {
				table.SetCell(0, i, tview.NewTableCell(header).
					SetTextColor(tcell.ColorYellow).
					SetAlign(tview.AlignCenter))
			}
			
			// Add connections
			for i := 0; i < count; i++ {
				row := i + 1
				table.SetCell(row, 0, tview.NewTableCell(fmt.Sprintf("192.168.1.%d:1234", i%256)))
				table.SetCell(row, 1, tview.NewTableCell(fmt.Sprintf("10.0.0.%d:80", i%256)))
				table.SetCell(row, 2, tview.NewTableCell("TCP"))
				table.SetCell(row, 3, tview.NewTableCell(fmt.Sprintf("%d KB", i*10)))
				table.SetCell(row, 4, tview.NewTableCell(fmt.Sprintf("%d KB", i*5)))
			}
			
			screen := NewMockScreen(120, 40)
			
			b.ResetTimer()
			b.ReportAllocs()
			
			for i := 0; i < b.N; i++ {
				// Simulate rendering
				table.Draw(screen)
			}
		})
	}
}

// BenchmarkStatusBarUpdate benchmarks status bar updates
func BenchmarkStatusBarUpdate(b *testing.B) {
	statusBar := tview.NewTextView()
	
	templates := []string{
		"[yellow]↓[white] %s [yellow]↑[white] %s [yellow]Σ[white] %s [yellow]⚡[white] %d pkt/s",
		"CPU: %.1f%% | Memory: %.1f%% | Connections: %d | Uptime: %s",
		"Interface: %s | Filter: %s | Packets: %d | Dropped: %d",
	}
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		template := templates[i%len(templates)]
		var text string
		
		switch i % len(templates) {
		case 0:
			text = fmt.Sprintf(template, "1.5 MB/s", "750 KB/s", "2.25 MB/s", 1500)
		case 1:
			text = fmt.Sprintf(template, 45.2, 62.8, 152, "2h 15m")
		case 2:
			text = fmt.Sprintf(template, "eth0", "tcp port 80", 1000000, 50)
		}
		
		statusBar.SetText(text)
	}
}

// BenchmarkDashboardLayout benchmarks dashboard layout calculations
func BenchmarkDashboardLayout(b *testing.B) {
	layouts := []struct {
		name string
		rows int
		cols int
	}{
		{"2x2", 2, 2},
		{"3x3", 3, 3},
		{"4x4", 4, 4},
	}
	
	for _, layout := range layouts {
		b.Run(layout.name, func(b *testing.B) {
			registry := NewVisualizationRegistry()
			monitor := netcap.NewNetworkMonitor()
			
			// Register visualizations
			registry.Register("matrix", NewMatrixRainVisualization)
			registry.Register("heatmap", NewHeatmapVisualization)
			registry.Register("speedometer", NewSpeedometerVisualization)
			registry.Register("sankey", NewSankeyVisualization)
			
			dashboard := NewDashboard(registry, monitor)
			
			// Create layout
			items := make([]DashboardVisualization, 0)
			vizTypes := []string{"matrix", "heatmap", "speedometer", "sankey"}
			
			for row := 0; row < layout.rows; row++ {
				for col := 0; col < layout.cols; col++ {
					items = append(items, DashboardVisualization{
						ID:      vizTypes[(row*layout.cols+col)%len(vizTypes)],
						Row:     row,
						Col:     col,
						RowSpan: 1,
						ColSpan: 1,
					})
				}
			}
			
			dashLayout := DashboardLayout{
				Name:           layout.name,
				Description:    "Benchmark layout",
				GridRows:       layout.rows,
				GridCols:       layout.cols,
				Visualizations: items,
			}
			
			b.ResetTimer()
			b.ReportAllocs()
			
			for i := 0; i < b.N; i++ {
				dashboard.SetLayout(dashLayout)
			}
		})
	}
}

// BenchmarkConcurrentUIUpdates benchmarks concurrent UI updates
func BenchmarkConcurrentUIUpdates(b *testing.B) {
	workers := []int{1, 2, 4, 8}
	
	for _, numWorkers := range workers {
		b.Run(fmt.Sprintf("Workers-%d", numWorkers), func(b *testing.B) {
			monitor := netcap.NewNetworkMonitor()
			ui := NewUI(monitor)
			
			b.ResetTimer()
			b.ReportAllocs()
			
			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					// Simulate various UI updates
					switch i % 4 {
					case 0:
						ui.SetTheme("Dark")
					case 1:
						ui.SetStyle("Rounded")
					case 2:
						ui.SetGradientEnabled(i%2 == 0)
					case 3:
						// Simulate traffic update
						monitor.Interfaces["test0"] = &netcap.InterfaceStats{
							BytesIn:  uint64(i * 1000),
							BytesOut: uint64(i * 500),
						}
					}
					i++
				}
			})
		})
	}
}