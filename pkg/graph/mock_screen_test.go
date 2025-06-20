package graph

import "github.com/gdamore/tcell/v2"

// MockScreen implements tcell.Screen for testing
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