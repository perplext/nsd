package ui

import (
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// StyledGrid is a custom grid implementation that supports styled borders
type StyledGrid struct {
	*tview.Box
	
	// Grid cells
	cells []*gridCell
	
	// Grid dimensions
	rows, columns int
	rowHeights []int
	columnWidths []int
	
	// Minimum dimensions
	minHeight, minWidth int
	
	// Border settings
	borders bool
	borderStyle BorderChars
	borderColor tcell.Color
	
	// Animation settings
	animation string
	animationFrame int
	
	// Gap between cells
	gap int
}

// gridCell represents a single cell in the grid
type gridCell struct {
	row, column int
	rowSpan, colSpan int
	primitive tview.Primitive
	focus bool
	borderStyle *BorderChars // Custom border style for this cell (nil uses grid default)
	borderAnimation string   // Custom animation for this cell
}

// NewStyledGrid creates a new styled grid
func NewStyledGrid() *StyledGrid {
	return &StyledGrid{
		Box:         tview.NewBox(),
		cells:       make([]*gridCell, 0),
		borders:     true,
		borderStyle: GetBorderStyle("Single"),
		borderColor: tcell.ColorWhite,
		gap:         0,
	}
}

// SetBorders enables or disables borders
func (g *StyledGrid) SetBorders(borders bool) *StyledGrid {
	g.borders = borders
	return g
}

// SetBorderStyle sets the border style
func (g *StyledGrid) SetBorderStyle(style string) *StyledGrid {
	g.borderStyle = GetBorderStyle(style)
	return g
}

// SetBorderColor sets the border color
func (g *StyledGrid) SetBorderColor(color tcell.Color) *StyledGrid {
	g.borderColor = color
	return g
}

// SetAnimation sets the border animation type
func (g *StyledGrid) SetAnimation(animation string) *StyledGrid {
	g.animation = animation
	return g
}

// SetAnimationFrame sets the current animation frame
func (g *StyledGrid) SetAnimationFrame(frame int) *StyledGrid {
	g.animationFrame = frame
	return g
}

// SetColumns defines column widths (0 means proportional)
func (g *StyledGrid) SetColumns(widths ...int) *StyledGrid {
	g.columns = len(widths)
	g.columnWidths = widths
	return g
}

// SetRows defines row heights (0 means proportional)
func (g *StyledGrid) SetRows(heights ...int) *StyledGrid {
	g.rows = len(heights)
	g.rowHeights = heights
	return g
}

// SetGap sets the gap between cells
func (g *StyledGrid) SetGap(gap int) *StyledGrid {
	g.gap = gap
	return g
}

// AddItem adds a primitive to the grid
func (g *StyledGrid) AddItem(p tview.Primitive, row, column, rowSpan, colSpan int, minGridHeight, minGridWidth int, focus bool) *StyledGrid {
	g.cells = append(g.cells, &gridCell{
		row:       row,
		column:    column,
		rowSpan:   rowSpan,
		colSpan:   colSpan,
		primitive: p,
		focus:     focus,
	})
	
	// Update minimum dimensions
	if minGridHeight > g.minHeight {
		g.minHeight = minGridHeight
	}
	if minGridWidth > g.minWidth {
		g.minWidth = minGridWidth
	}
	
	// Update grid dimensions
	if row+rowSpan > g.rows {
		g.rows = row + rowSpan
	}
	if column+colSpan > g.columns {
		g.columns = column + colSpan
	}
	
	return g
}

// AddItemWithStyle adds a primitive to the grid with custom border style
func (g *StyledGrid) AddItemWithStyle(p tview.Primitive, row, column, rowSpan, colSpan int, minGridHeight, minGridWidth int, focus bool, borderStyle string, borderAnimation string) *StyledGrid {
	var style *BorderChars
	if borderStyle != "" {
		s := GetBorderStyle(borderStyle)
		style = &s
	}
	
	g.cells = append(g.cells, &gridCell{
		row:             row,
		column:          column,
		rowSpan:         rowSpan,
		colSpan:         colSpan,
		primitive:       p,
		focus:           focus,
		borderStyle:     style,
		borderAnimation: borderAnimation,
	})
	
	// Update minimum dimensions
	if minGridHeight > g.minHeight {
		g.minHeight = minGridHeight
	}
	if minGridWidth > g.minWidth {
		g.minWidth = minGridWidth
	}
	
	// Update grid dimensions
	if row+rowSpan > g.rows {
		g.rows = row + rowSpan
	}
	if column+colSpan > g.columns {
		g.columns = column + colSpan
	}
	
	return g
}

// Clear removes all items from the grid
func (g *StyledGrid) Clear() *StyledGrid {
	g.cells = nil
	return g
}

// Draw draws the grid
func (g *StyledGrid) Draw(screen tcell.Screen) {
	g.Box.DrawForSubclass(screen, g)
	
	x, y, width, height := g.GetInnerRect()
	
	// Calculate actual row heights and column widths
	rowHeights := g.calculateDimensions(height, g.rows, g.rowHeights, g.borders)
	colWidths := g.calculateDimensions(width, g.columns, g.columnWidths, g.borders)
	
	// Draw borders if enabled
	if g.borders {
		g.drawBorders(screen, x, y, rowHeights, colWidths)
	}
	
	// Draw cells
	for _, cell := range g.cells {
		if cell.primitive == nil {
			continue
		}
		
		// Calculate cell position and size
		cellX, cellY := x, y
		cellWidth, cellHeight := 0, 0
		
		// Calculate X position and width
		for i := 0; i < cell.column; i++ {
			cellX += colWidths[i]
			if g.borders {
				cellX++ // Border width
			}
		}
		for i := 0; i < cell.colSpan && cell.column+i < len(colWidths); i++ {
			cellWidth += colWidths[cell.column+i]
			if g.borders && i > 0 {
				cellWidth++ // Border between cells
			}
		}
		
		// Calculate Y position and height
		for i := 0; i < cell.row; i++ {
			cellY += rowHeights[i]
			if g.borders {
				cellY++ // Border height
			}
		}
		for i := 0; i < cell.rowSpan && cell.row+i < len(rowHeights); i++ {
			cellHeight += rowHeights[cell.row+i]
			if g.borders && i > 0 {
				cellHeight++ // Border between cells
			}
		}
		
		// Apply gap
		if g.gap > 0 {
			cellX += g.gap
			cellY += g.gap
			cellWidth -= 2 * g.gap
			cellHeight -= 2 * g.gap
		}
		
		// Set primitive position and draw
		if cellWidth > 0 && cellHeight > 0 {
			cell.primitive.SetRect(cellX, cellY, cellWidth, cellHeight)
			cell.primitive.Draw(screen)
		}
	}
}

// drawBorders draws the grid borders with the selected style
func (g *StyledGrid) drawBorders(screen tcell.Screen, x, y int, rowHeights, colWidths []int) {
	// Get animated color if animation is enabled
	borderColor := g.borderColor
	if g.animation != "None" && g.animation != "" {
		borderColor = GetAnimatedBorderColor(g.borderColor, g.animation, g.animationFrame)
	}
	style := tcell.StyleDefault.Foreground(borderColor).Background(tcell.ColorDefault)
	
	// Calculate grid positions
	rowPositions := make([]int, len(rowHeights)+1)
	colPositions := make([]int, len(colWidths)+1)
	
	rowPositions[0] = y - 1
	for i, h := range rowHeights {
		rowPositions[i+1] = rowPositions[i] + h + 1
	}
	
	colPositions[0] = x - 1
	for i, w := range colWidths {
		colPositions[i+1] = colPositions[i] + w + 1
	}
	
	// Draw horizontal lines
	for _, rowY := range rowPositions {
		for j := 0; j < len(colPositions)-1; j++ {
			startX := colPositions[j]
			endX := colPositions[j+1]
			
			for x := startX + 1; x < endX; x++ {
				screen.SetContent(x, rowY, g.borderStyle.Horizontal, nil, style)
			}
		}
	}
	
	// Draw vertical lines
	for _, colX := range colPositions {
		for j := 0; j < len(rowPositions)-1; j++ {
			startY := rowPositions[j]
			endY := rowPositions[j+1]
			
			for y := startY + 1; y < endY; y++ {
				screen.SetContent(colX, y, g.borderStyle.Vertical, nil, style)
			}
		}
	}
	
	// Draw corners and intersections
	for i, rowY := range rowPositions {
		for j, colX := range colPositions {
			var ch rune
			
			// Determine which character to use based on position
			if i == 0 && j == 0 {
				ch = g.borderStyle.TopLeft
			} else if i == 0 && j == len(colPositions)-1 {
				ch = g.borderStyle.TopRight
			} else if i == len(rowPositions)-1 && j == 0 {
				ch = g.borderStyle.BottomLeft
			} else if i == len(rowPositions)-1 && j == len(colPositions)-1 {
				ch = g.borderStyle.BottomRight
			} else if i == 0 {
				ch = g.borderStyle.HorizontalDown
			} else if i == len(rowPositions)-1 {
				ch = g.borderStyle.HorizontalUp
			} else if j == 0 {
				ch = g.borderStyle.VerticalRight
			} else if j == len(colPositions)-1 {
				ch = g.borderStyle.VerticalLeft
			} else {
				ch = g.borderStyle.Cross
			}
			
			screen.SetContent(colX, rowY, ch, nil, style)
		}
	}
}

// calculateDimensions calculates actual dimensions based on available space
func (g *StyledGrid) calculateDimensions(available, count int, specified []int, borders bool) []int {
	if count == 0 {
		return nil
	}
	
	// Account for borders
	if borders {
		available -= count + 1
	}
	
	result := make([]int, count)
	totalFixed := 0
	proportionalCount := 0
	
	// First pass: count fixed sizes and proportional cells
	for i := 0; i < count; i++ {
		if i < len(specified) && specified[i] > 0 {
			result[i] = specified[i]
			totalFixed += specified[i]
		} else {
			proportionalCount++
		}
	}
	
	// Second pass: distribute remaining space
	if proportionalCount > 0 && available > totalFixed {
		proportionalSize := (available - totalFixed) / proportionalCount
		remainder := (available - totalFixed) % proportionalCount
		
		for i := 0; i < count; i++ {
			if i >= len(specified) || specified[i] == 0 {
				result[i] = proportionalSize
				if remainder > 0 {
					result[i]++
					remainder--
				}
			}
		}
	}
	
	return result
}

// Focus passes focus to the appropriate cell
func (g *StyledGrid) Focus(delegate func(p tview.Primitive)) {
	for _, cell := range g.cells {
		if cell.focus && cell.primitive != nil {
			delegate(cell.primitive)
			return
		}
	}
	
	// No focus cell found, focus first available
	for _, cell := range g.cells {
		if cell.primitive != nil {
			delegate(cell.primitive)
			return
		}
	}
}

// HasFocus returns whether any cell has focus
func (g *StyledGrid) HasFocus() bool {
	for _, cell := range g.cells {
		if cell.primitive != nil && cell.primitive.HasFocus() {
			return true
		}
	}
	return false
}

// InputHandler returns the handler for this primitive
func (g *StyledGrid) InputHandler() func(event *tcell.EventKey, setFocus func(p tview.Primitive)) {
	return g.WrapInputHandler(func(event *tcell.EventKey, setFocus func(p tview.Primitive)) {
		// Find focused cell
		for _, cell := range g.cells {
			if cell.primitive != nil && cell.primitive.HasFocus() {
				if handler := cell.primitive.InputHandler(); handler != nil {
					handler(event, setFocus)
					return
				}
			}
		}
	})
}

// MouseHandler returns the mouse handler for this primitive
func (g *StyledGrid) MouseHandler() func(action tview.MouseAction, event *tcell.EventMouse, setFocus func(p tview.Primitive)) (consumed bool, capture tview.Primitive) {
	return g.WrapMouseHandler(func(action tview.MouseAction, event *tcell.EventMouse, setFocus func(p tview.Primitive)) (consumed bool, capture tview.Primitive) {
		// Pass mouse events to cells
		for _, cell := range g.cells {
			if cell.primitive != nil {
				if handler := cell.primitive.MouseHandler(); handler != nil {
					consumed, capture = handler(action, event, setFocus)
					if consumed {
						return
					}
				}
			}
		}
		return false, nil
	})
}