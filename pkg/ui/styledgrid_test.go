package ui

import (
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStyledGrid(t *testing.T) {
	grid := NewStyledGrid()
	assert.NotNil(t, grid)
	assert.NotNil(t, grid.Box)
	assert.NotNil(t, grid.cells)
	assert.Equal(t, 0, len(grid.cells))
	assert.True(t, grid.borders) // borders enabled by default
}

func TestStyledGridSetBorders(t *testing.T) {
	grid := NewStyledGrid()
	
	// Test enabling borders
	result := grid.SetBorders(true)
	assert.Equal(t, grid, result)
	assert.True(t, grid.borders)
	
	// Test disabling borders
	grid.SetBorders(false)
	assert.False(t, grid.borders)
}

func TestStyledGridSetBorderStyle(t *testing.T) {
	grid := NewStyledGrid()
	
	// Test setting border style with string
	result := grid.SetBorderStyle("Double")
	assert.Equal(t, grid, result)
	assert.Equal(t, GetBorderStyle("Double"), grid.borderStyle)
	
	// Test different border styles
	styles := []string{"Single", "Rounded", "Thick", "Dashed", "Dotted"}
	for _, style := range styles {
		grid.SetBorderStyle(style)
		assert.Equal(t, GetBorderStyle(style), grid.borderStyle)
	}
}

func TestStyledGridSetBorderColor(t *testing.T) {
	grid := NewStyledGrid()
	
	// Test setting border color
	color := tcell.ColorRed
	result := grid.SetBorderColor(color)
	assert.Equal(t, grid, result)
	assert.Equal(t, color, grid.borderColor)
}

func TestStyledGridSetAnimation(t *testing.T) {
	grid := NewStyledGrid()
	
	// Test setting animation
	result := grid.SetAnimation("rainbow")
	assert.Equal(t, grid, result)
	assert.Equal(t, "rainbow", grid.animation)
	
	// Test different animation types
	animations := []string{"pulse", "fire", "matrix", "wave", "sparkle", "none"}
	for _, anim := range animations {
		grid.SetAnimation(anim)
		assert.Equal(t, anim, grid.animation)
	}
}

func TestStyledGridSetAnimationFrame(t *testing.T) {
	grid := NewStyledGrid()
	
	// Test setting animation frame
	result := grid.SetAnimationFrame(42)
	assert.Equal(t, grid, result)
	assert.Equal(t, 42, grid.animationFrame)
}

func TestStyledGridSetGap(t *testing.T) {
	grid := NewStyledGrid()
	
	// Test setting gap
	result := grid.SetGap(2)
	assert.Equal(t, grid, result)
	assert.Equal(t, 2, grid.gap)
	
	// Test different gap values
	gaps := []int{0, 1, 3, 5}
	for _, gap := range gaps {
		grid.SetGap(gap)
		assert.Equal(t, gap, grid.gap)
	}
}

func TestStyledGridSetRowsColumns(t *testing.T) {
	grid := NewStyledGrid()
	
	// Test setting rows
	result := grid.SetRows(3, 2, 1)
	assert.Equal(t, grid, result)
	assert.Equal(t, 3, len(grid.rowHeights))
	assert.Equal(t, 3, grid.rowHeights[0])
	assert.Equal(t, 2, grid.rowHeights[1])
	assert.Equal(t, 1, grid.rowHeights[2])
	
	// Test setting columns
	grid.SetColumns(4, 3, 2, 1)
	assert.Equal(t, 4, len(grid.columnWidths))
	assert.Equal(t, 4, grid.columnWidths[0])
	assert.Equal(t, 3, grid.columnWidths[1])
	assert.Equal(t, 2, grid.columnWidths[2])
	assert.Equal(t, 1, grid.columnWidths[3])
}

func TestStyledGridAddItem(t *testing.T) {
	grid := NewStyledGrid()
	
	// Create test primitives
	text1 := tview.NewTextView()
	text2 := tview.NewTextView()
	
	// Test adding items
	result := grid.AddItem(text1, 0, 0, 1, 1, 10, 5, false)
	assert.Equal(t, grid, result)
	assert.Equal(t, 1, len(grid.cells))
	
	// Add another item
	grid.AddItem(text2, 1, 0, 1, 2, 20, 10, true)
	assert.Equal(t, 2, len(grid.cells))
	
	// Check first cell properties
	cell1 := grid.cells[0]
	assert.Equal(t, 0, cell1.row)
	assert.Equal(t, 0, cell1.column)
	assert.Equal(t, 1, cell1.rowSpan)
	assert.Equal(t, 1, cell1.colSpan)
	assert.Equal(t, text1, cell1.primitive)
	assert.False(t, cell1.focus)
	
	// Check second cell properties
	cell2 := grid.cells[1]
	assert.Equal(t, 1, cell2.row)
	assert.Equal(t, 0, cell2.column)
	assert.Equal(t, 1, cell2.rowSpan)
	assert.Equal(t, 2, cell2.colSpan)
	assert.Equal(t, text2, cell2.primitive)
	assert.True(t, cell2.focus)
}

func TestStyledGridAddItemWithStyle(t *testing.T) {
	grid := NewStyledGrid()
	
	// Create test primitive
	text := tview.NewTextView()
	
	// Test adding item with custom style
	result := grid.AddItemWithStyle(text, 0, 0, 1, 1, 10, 5, false, "Double", "rainbow")
	assert.Equal(t, grid, result)
	assert.Equal(t, 1, len(grid.cells))
	
	// Check cell properties
	cell := grid.cells[0]
	assert.Equal(t, text, cell.primitive)
	assert.NotNil(t, cell.borderStyle)
	assert.Equal(t, GetBorderStyle("Double"), *cell.borderStyle)
	assert.Equal(t, "rainbow", cell.borderAnimation)
}

func TestStyledGridClear(t *testing.T) {
	grid := NewStyledGrid()
	
	// Add some items
	text1 := tview.NewTextView()
	text2 := tview.NewTextView()
	grid.AddItem(text1, 0, 0, 1, 1, 10, 5, false)
	grid.AddItem(text2, 1, 0, 1, 1, 10, 5, false)
	assert.Equal(t, 2, len(grid.cells))
	
	// Clear all items
	result := grid.Clear()
	assert.Equal(t, grid, result)
	assert.Equal(t, 0, len(grid.cells))
}

func TestStyledGridDraw(t *testing.T) {
	grid := NewStyledGrid()
	
	// Create mock screen
	screen := tcell.NewSimulationScreen("UTF-8")
	err := screen.Init()
	require.NoError(t, err)
	defer screen.Fini()
	
	screen.SetSize(80, 24)
	grid.SetRect(0, 0, 80, 24)
	
	// Test drawing empty grid
	grid.Draw(screen)
	
	// Test drawing with borders
	grid.SetBorders(true)
	grid.SetBorderStyle("Single")
	grid.Draw(screen)
	
	// Test drawing with animation
	grid.SetAnimation("rainbow")
	grid.Draw(screen)
	
	// Test drawing with content
	text := tview.NewTextView()
	text.SetText("Test content")
	grid.AddItem(text, 0, 0, 1, 1, 10, 5, false)
	grid.Draw(screen)
}

func TestStyledGridFocus(t *testing.T) {
	grid := NewStyledGrid()
	
	// Add items
	text1 := tview.NewTextView()
	text2 := tview.NewTextView()
	grid.AddItem(text1, 0, 0, 1, 1, 10, 5, false)
	grid.AddItem(text2, 1, 0, 1, 1, 10, 5, true) // This one has focus
	
	// Test focus delegation
	focusCalled := false
	var focusedPrimitive tview.Primitive
	
	grid.Focus(func(p tview.Primitive) {
		focusCalled = true
		focusedPrimitive = p
	})
	
	assert.True(t, focusCalled)
	assert.Equal(t, text2, focusedPrimitive) // Should focus the item marked with focus=true
}

func TestStyledGridHasFocus(t *testing.T) {
	grid := NewStyledGrid()
	
	// Add focusable item
	input := tview.NewInputField()
	grid.AddItem(input, 0, 0, 1, 1, 10, 5, true)
	
	// Test HasFocus
	hasFocus := grid.HasFocus()
	// Since we can't actually set focus without running the app, 
	// just test that the method doesn't panic
	assert.False(t, hasFocus) // Initially false
}

func TestStyledGridInputHandler(t *testing.T) {
	grid := NewStyledGrid()
	
	// Add input field
	input := tview.NewInputField()
	grid.AddItem(input, 0, 0, 1, 1, 10, 5, true)
	
	// Get input handler
	handler := grid.InputHandler()
	assert.NotNil(t, handler)
	
	// Test with key event
	event := tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone)
	assert.NotPanics(t, func() {
		handler(event, nil)
	})
}

func TestStyledGridMouseHandler(t *testing.T) {
	grid := NewStyledGrid()
	
	// Add button
	button := tview.NewButton("Test")
	grid.AddItem(button, 0, 0, 1, 1, 10, 5, false)
	
	// Get mouse handler
	handler := grid.MouseHandler()
	assert.NotNil(t, handler)
	
	// Test with mouse event
	event := tcell.NewEventMouse(10, 5, tcell.Button1, tcell.ModNone)
	assert.NotPanics(t, func() {
		consumed, capture := handler(tview.MouseAction(1), event, nil)
		_ = consumed
		_ = capture
	})
}

func TestStyledGridComplexLayout(t *testing.T) {
	grid := NewStyledGrid()
	
	// Create complex layout
	grid.SetRows(3, -1, 2)
	grid.SetColumns(20, -1, 20)
	grid.SetGap(1)
	grid.SetBorders(true)
	grid.SetBorderStyle("Rounded")
	grid.SetAnimation("matrix")
	
	// Add multiple items
	items := []tview.Primitive{
		tview.NewTextView(),
		tview.NewButton("Button"),
		tview.NewInputField(),
		tview.NewList(),
	}
	
	grid.AddItem(items[0], 0, 0, 1, 1, 10, 5, false)
	grid.AddItem(items[1], 0, 1, 1, 2, 20, 10, false)
	grid.AddItem(items[2], 1, 0, 1, 3, 30, 15, true)
	grid.AddItem(items[3], 2, 1, 1, 1, 15, 8, false)
	
	assert.Equal(t, 4, len(grid.cells))
}

func TestStyledGridEdgeCases(t *testing.T) {
	grid := NewStyledGrid()
	
	// Test with nil primitive (should handle gracefully)
	assert.NotPanics(t, func() {
		grid.AddItem(nil, 0, 0, 1, 1, 10, 5, false)
	})
	
	// Test with negative positions/spans
	text := tview.NewTextView()
	assert.NotPanics(t, func() {
		grid.AddItem(text, -1, -1, -1, -1, 10, 5, false)
	})
}

func TestStyledGridChaining(t *testing.T) {
	grid := NewStyledGrid()
	
	// Test method chaining
	result := grid.
		SetBorders(true).
		SetAnimation("pulse").
		SetGap(2).
		SetBorderColor(tcell.ColorRed)
	
	assert.Equal(t, grid, result)
	assert.True(t, grid.borders)
	assert.Equal(t, "pulse", grid.animation)
	assert.Equal(t, 2, grid.gap)
	assert.Equal(t, tcell.ColorRed, grid.borderColor)
}