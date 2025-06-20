package graph

import (
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/stretchr/testify/assert"
)

// Simple mock screen that implements only what we need
type SimpleScreen struct {
	width, height int
	drawCalled    bool
}

func (s *SimpleScreen) SetContent(x, y int, mainc rune, combc []rune, style tcell.Style) {}
func (s *SimpleScreen) GetContent(x, y int) (mainc rune, combc []rune, style tcell.Style, width int) {
	return ' ', nil, tcell.StyleDefault, 1
}
func (s *SimpleScreen) Size() (width, height int)                           { return s.width, s.height }
func (s *SimpleScreen) Clear()                                               {}
func (s *SimpleScreen) Fill(rune, tcell.Style)                              {}
func (s *SimpleScreen) SetStyle(tcell.Style)                                {}
func (s *SimpleScreen) ShowCursor(int, int)                                 {}
func (s *SimpleScreen) HideCursor()                                         {}
func (s *SimpleScreen) SetCursorStyle(tcell.CursorStyle)                    {}
func (s *SimpleScreen) GetCursorStyle() tcell.CursorStyle                   { return tcell.CursorStyleDefault }
func (s *SimpleScreen) CanDisplay(rune, bool) bool                          { return true }
func (s *SimpleScreen) CharacterSet() string                                { return "UTF-8" }
func (s *SimpleScreen) RegisterRuneFallback(rune, string)                   {}
func (s *SimpleScreen) UnregisterRuneFallback(rune)                         {}
func (s *SimpleScreen) HasMouse() bool                                      { return false }
func (s *SimpleScreen) EnableMouse(...tcell.MouseFlags)                     {}
func (s *SimpleScreen) DisableMouse()                                        {}
func (s *SimpleScreen) EnablePaste()                                         {}
func (s *SimpleScreen) DisablePaste()                                        {}
func (s *SimpleScreen) HasKey(tcell.Key) bool                               { return true }
func (s *SimpleScreen) Show()                                                { s.drawCalled = true }
func (s *SimpleScreen) Sync()                                                {}
func (s *SimpleScreen) Resize(int, int, int, int)                           {}
func (s *SimpleScreen) SetSize(int, int)                                    {}
func (s *SimpleScreen) Init() error                                          { return nil }
func (s *SimpleScreen) Fini()                                                {}
func (s *SimpleScreen) PollEvent() tcell.Event                              { return nil }
func (s *SimpleScreen) PostEvent(ev tcell.Event) error                      { return nil }
func (s *SimpleScreen) ChannelEvents(ch chan<- tcell.Event, quit <-chan struct{}) {}
func (s *SimpleScreen) PostEventWait(tcell.Event)                           {}
func (s *SimpleScreen) EnableFocus()                                         {}
func (s *SimpleScreen) DisableFocus()                                        {}
func (s *SimpleScreen) Beep() error                                         { return nil }
func (s *SimpleScreen) Suspend() error                                      { return nil }
func (s *SimpleScreen) Resume() error                                       { return nil }
func (s *SimpleScreen) LockRegion(x, y, width, height int, lock bool)       {}
func (s *SimpleScreen) Tty() (tcell.Tty, bool)                             { return nil, false }
func (s *SimpleScreen) Colors() int                                         { return 256 }
func (s *SimpleScreen) GetClipboard()                                       {}
func (s *SimpleScreen) SetClipboard([]byte)                                 {}

// Test Draw method paths
func TestGraph_DrawPaths(t *testing.T) {
	// Test with various configurations to hit different code paths
	tests := []struct {
		name   string
		setup  func(*Graph)
		width  int
		height int
	}{
		{
			name: "Small dimensions",
			setup: func(g *Graph) {
				g.SetTitle("Test")
			},
			width:  5,
			height: 2,
		},
		{
			name: "Normal with title",
			setup: func(g *Graph) {
				g.SetTitle("Graph Title")
				g.AddPoint(50)
			},
			width:  80,
			height: 20,
		},
		{
			name: "With legend",
			setup: func(g *Graph) {
				g.ShowLegend(true)
				g.SetLabels("In", "Out")
				g.AddDualPoint(100, 50)
			},
			width:  60,
			height: 15,
		},
		{
			name: "Braille style",
			setup: func(g *Graph) {
				g.SetStyle(StyleBraille)
				for i := 0; i < 20; i++ {
					g.AddPoint(float64(i * 10))
				}
			},
			width:  40,
			height: 10,
		},
		{
			name: "Block style",
			setup: func(g *Graph) {
				g.SetStyle(StyleBlock)
				for i := 0; i < 10; i++ {
					g.AddDualPoint(float64(i*5), float64(i*3))
				}
			},
			width:  40,
			height: 10,
		},
		{
			name: "TTY style",
			setup: func(g *Graph) {
				g.SetStyle(StyleTTY)
				for i := 0; i < 15; i++ {
					g.AddPoint(float64(i * 7))
				}
			},
			width:  40,
			height: 10,
		},
		{
			name: "Empty data",
			setup: func(g *Graph) {
				g.data = nil
				g.secondaryData = nil
			},
			width:  40,
			height: 10,
		},
		{
			name: "With gradient",
			setup: func(g *Graph) {
				g.SetGradientEnabled(true)
				g.SetColor(tcell.ColorGreen)
				for i := 0; i < 30; i++ {
					g.AddPoint(float64(i * 3))
				}
			},
			width:  50,
			height: 12,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewGraph()
			g.SetRect(0, 0, tt.width, tt.height)
			tt.setup(g)
			
			screen := &SimpleScreen{width: tt.width, height: tt.height}
			
			// Should not panic
			assert.NotPanics(t, func() {
				g.Draw(screen)
			})
		})
	}
}

// Test MultiGraph Draw
func TestMultiGraph_Draw(t *testing.T) {
	mg := NewMultiGraph()
	mg.SetTitle("Multi Graph Test")
	mg.ShowTitle(true)
	mg.SetRect(0, 0, 80, 24)
	
	// Add graph widgets
	for i := 0; i < 4; i++ {
		w := NewGraphWidget()
		w.SetLabels("Primary", "Secondary")
		w.SetDataFunc(func() (float64, float64) {
			return float64(i * 10), float64(i * 5)
		})
		mg.AddGraph(w)
	}
	
	screen := &SimpleScreen{width: 80, height: 24}
	
	// Should not panic
	assert.NotPanics(t, func() {
		mg.Draw(screen)
	})
}

// Test edge cases in drawing
func TestGraph_DrawEdgeCases(t *testing.T) {
	g := NewGraph()
	
	// Test with very small graph area (after labels)
	g.SetRect(0, 0, 15, 5)
	screen := &SimpleScreen{width: 15, height: 5}
	assert.NotPanics(t, func() {
		g.Draw(screen)
	})
	
	// Test with large values requiring T suffix
	g.SetRect(0, 0, 50, 10)
	g.SetMaxValue(1000000000000) // 1T
	screen = &SimpleScreen{width: 50, height: 10}
	assert.NotPanics(t, func() {
		g.Draw(screen)
	})
}