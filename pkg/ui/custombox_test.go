package ui

import (
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCustomBox(t *testing.T) {
	content := tview.NewTextView()
	box := NewCustomBox(content)
	assert.NotNil(t, box)
	assert.NotNil(t, box.Box)
	assert.NotNil(t, box.content)
	assert.True(t, box.border) // border is true by default
}

func TestCustomBoxSetTitle(t *testing.T) {
	content := tview.NewTextView()
	box := NewCustomBox(content)
	
	// Test setting title
	title := "Test Title"
	result := box.SetTitle(title)
	assert.Equal(t, box, result) // Should return self for chaining
	assert.Equal(t, title, box.title)
	
	// Test setting empty title
	emptyResult := box.SetTitle("")
	assert.Equal(t, box, emptyResult)
	assert.Equal(t, "", box.title)
	
	// Test setting title with special characters
	specialTitle := "Title with 🎨 and [red]colors[white]"
	box.SetTitle(specialTitle)
	assert.Equal(t, specialTitle, box.title)
}

func TestCustomBoxSetBorder(t *testing.T) {
	content := tview.NewTextView()
	box := NewCustomBox(content)
	
	// Test enabling border
	result := box.SetBorder(true)
	assert.Equal(t, box, result)
	assert.True(t, box.border)
	
	// Test disabling border
	box.SetBorder(false)
	assert.False(t, box.border)
}

func TestCustomBoxSetBorderStyle(t *testing.T) {
	content := tview.NewTextView()
	box := NewCustomBox(content)
	
	// Test setting border style
	style := GetBorderStyle("Double")
	result := box.SetBorderStyle(style)
	assert.Equal(t, box, result)
	assert.Equal(t, style, box.style)
	
	// Test different border styles
	styles := []string{
		"Single", "Double", "Rounded", "Thick", "Dashed", "Dotted",
	}
	
	for _, s := range styles {
		borderStyle := GetBorderStyle(s)
		box.SetBorderStyle(borderStyle)
		assert.Equal(t, borderStyle, box.style)
	}
}

func TestCustomBoxDraw(t *testing.T) {
	content := tview.NewTextView()
	content.SetText("Test content")
	box := NewCustomBox(content)
	
	// Create a mock screen for testing
	screen := tcell.NewSimulationScreen("UTF-8")
	err := screen.Init()
	require.NoError(t, err)
	defer screen.Fini()
	
	// Set screen size
	screen.SetSize(80, 24)
	box.SetRect(10, 5, 60, 14)
	
	// Test drawing without border
	box.SetBorder(false)
	box.Draw(screen)
	
	// Test drawing with border
	box.SetBorder(true)
	box.SetTitle("Test")
	box.Draw(screen)
	
	// Test drawing with different border styles
	box.SetBorderStyle(GetBorderStyle("Double"))
	box.Draw(screen)
	
	// Should not panic
	assert.True(t, true)
}

func TestCustomBoxFocus(t *testing.T) {
	content := tview.NewTextView()
	box := NewCustomBox(content)
	
	// Test focus delegation
	focusCalled := false
	box.Focus(func(p tview.Primitive) {
		focusCalled = true
		assert.Equal(t, content, p)
	})
	assert.True(t, focusCalled)
}

func TestCustomBoxHasFocus(t *testing.T) {
	content := tview.NewInputField() // InputField can have focus
	box := NewCustomBox(content)
	
	// Initially no focus
	assert.False(t, box.HasFocus())
	
	// Set focus on content
	content.Focus(nil)
	// Note: HasFocus depends on the content's focus state
}

func TestCustomBoxInputHandler(t *testing.T) {
	content := tview.NewInputField()
	box := NewCustomBox(content)
	
	// Get input handler
	handler := box.InputHandler()
	assert.NotNil(t, handler)
	
	// Test with various key events
	events := []*tcell.EventKey{
		tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone),
		tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone),
		tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone),
		tcell.NewEventKey(tcell.KeyRune, 'a', tcell.ModNone),
	}
	
	for _, event := range events {
		// Should not panic
		assert.NotPanics(t, func() {
			handler(event, nil)
		})
	}
}

func TestCustomBoxMouseHandler(t *testing.T) {
	content := tview.NewButton("Test")
	box := NewCustomBox(content)
	
	// Get mouse handler
	handler := box.MouseHandler()
	assert.NotNil(t, handler)
	
	// Test with various mouse events
	events := []*tcell.EventMouse{
		tcell.NewEventMouse(10, 5, tcell.Button1, tcell.ModNone),
		tcell.NewEventMouse(20, 10, tcell.Button2, tcell.ModNone),
		tcell.NewEventMouse(30, 15, tcell.Button3, tcell.ModNone),
		tcell.NewEventMouse(15, 8, tcell.ButtonNone, tcell.ModNone), // Mouse move
	}
	
	for _, event := range events {
		// Should not panic
		assert.NotPanics(t, func() {
			consumed, capture := handler(tview.MouseAction(1), event, nil)
			_ = consumed // Handler may or may not consume the event
			_ = capture
		})
	}
}

func TestCustomBoxChaining(t *testing.T) {
	content := tview.NewTextView()
	box := NewCustomBox(content)
	
	// Test method chaining
	result := box.
		SetTitle("Chained Title").
		SetBorder(true).
		SetBorderStyle(GetBorderStyle("Rounded"))
	
	assert.Equal(t, box, result)
	assert.Equal(t, "Chained Title", box.title)
	assert.True(t, box.border)
	assert.Equal(t, GetBorderStyle("Rounded"), box.style)
}

func TestCustomBoxWithComplexContent(t *testing.T) {
	// Create a text view with content
	textView := tview.NewTextView()
	textView.SetText("This is test content\nWith multiple lines\nAnd some formatting")
	textView.SetDynamicColors(true)
	
	box := NewCustomBox(textView)
	box.SetTitle("Complex Content Test")
	box.SetBorder(true)
	box.SetBorderStyle(GetBorderStyle("Double"))
	
	// Create mock screen for drawing
	screen := tcell.NewSimulationScreen("UTF-8")
	err := screen.Init()
	require.NoError(t, err)
	defer screen.Fini()
	
	screen.SetSize(80, 24)
	box.SetRect(5, 5, 70, 14)
	
	// Should draw without panic
	assert.NotPanics(t, func() {
		box.Draw(screen)
	})
}

func TestCustomBoxResize(t *testing.T) {
	content := tview.NewTextView()
	box := NewCustomBox(content)
	box.SetBorder(true)
	box.SetTitle("Resize Test")
	
	// Create screen
	screen := tcell.NewSimulationScreen("UTF-8")
	err := screen.Init()
	require.NoError(t, err)
	defer screen.Fini()
	
	// Test different screen sizes
	sizes := []struct{ width, height int }{
		{20, 10},
		{40, 20},
		{80, 24},
		{120, 40},
		{10, 5}, // Edge case: small
	}
	
	for _, size := range sizes {
		screen.SetSize(size.width, size.height)
		box.SetRect(1, 1, size.width-2, size.height-2)
		assert.NotPanics(t, func() {
			box.Draw(screen)
		}, "Should not panic with size %dx%d", size.width, size.height)
	}
}

func TestCustomBoxNilContent(t *testing.T) {
	// Test with nil content (should handle gracefully)
	box := &CustomBox{
		Box:     tview.NewBox(),
		content: nil,
		border:  true,
		style:   GetBorderStyle("Single"),
	}
	
	// Should not panic with nil content
	assert.False(t, box.HasFocus())
	
	handler := box.InputHandler()
	assert.NotNil(t, handler)
	
	mouseHandler := box.MouseHandler()
	assert.NotNil(t, mouseHandler)
	
	// Drawing should not panic
	screen := tcell.NewSimulationScreen("UTF-8")
	err := screen.Init()
	require.NoError(t, err)
	defer screen.Fini()
	
	screen.SetSize(40, 20)
	box.SetRect(5, 5, 30, 10)
	
	assert.NotPanics(t, func() {
		box.Draw(screen)
	})
}

func TestCustomBoxLongTitle(t *testing.T) {
	content := tview.NewTextView()
	box := NewCustomBox(content)
	box.SetBorder(true)
	
	// Create screen
	screen := tcell.NewSimulationScreen("UTF-8")
	err := screen.Init()
	require.NoError(t, err)
	defer screen.Fini()
	
	screen.SetSize(40, 20)
	box.SetRect(5, 5, 20, 10) // Small box
	
	// Test with very long title (should be truncated)
	longTitle := "This is a very long title that should be truncated because it's too long for the box"
	box.SetTitle(longTitle)
	
	assert.NotPanics(t, func() {
		box.Draw(screen)
	})
}