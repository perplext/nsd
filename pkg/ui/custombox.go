package ui

import (
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// CustomBox wraps a primitive with custom border characters
type CustomBox struct {
	*tview.Box
	content  tview.Primitive
	title    string
	border   bool
	style    BorderChars
}

// NewCustomBox creates a new custom box with content
func NewCustomBox(content tview.Primitive) *CustomBox {
	return &CustomBox{
		Box:     tview.NewBox(),
		content: content,
		border:  true,
		style:   GetBorderStyle("Single"),
	}
}

// SetTitle sets the box title
func (c *CustomBox) SetTitle(title string) *CustomBox {
	c.title = title
	return c
}

// SetBorder enables/disables the border
func (c *CustomBox) SetBorder(show bool) *CustomBox {
	c.border = show
	return c
}

// SetBorderStyle sets the border style
func (c *CustomBox) SetBorderStyle(style BorderChars) *CustomBox {
	c.style = style
	return c
}

// Draw draws the box with custom borders
func (c *CustomBox) Draw(screen tcell.Screen) {
	c.Box.DrawForSubclass(screen, c)
	x, y, width, height := c.GetInnerRect()
	
	if c.border && width > 0 && height > 0 {
		// Draw border
		borderColor := c.GetBorderColor()
		
		// Top border
		screen.SetContent(x-1, y-1, c.style.TopLeft, nil, tcell.StyleDefault.Foreground(borderColor))
		screen.SetContent(x+width, y-1, c.style.TopRight, nil, tcell.StyleDefault.Foreground(borderColor))
		for i := x; i < x+width; i++ {
			screen.SetContent(i, y-1, c.style.Horizontal, nil, tcell.StyleDefault.Foreground(borderColor))
		}
		
		// Bottom border
		screen.SetContent(x-1, y+height, c.style.BottomLeft, nil, tcell.StyleDefault.Foreground(borderColor))
		screen.SetContent(x+width, y+height, c.style.BottomRight, nil, tcell.StyleDefault.Foreground(borderColor))
		for i := x; i < x+width; i++ {
			screen.SetContent(i, y+height, c.style.Horizontal, nil, tcell.StyleDefault.Foreground(borderColor))
		}
		
		// Side borders
		for i := y; i < y+height; i++ {
			screen.SetContent(x-1, i, c.style.Vertical, nil, tcell.StyleDefault.Foreground(borderColor))
			screen.SetContent(x+width, i, c.style.Vertical, nil, tcell.StyleDefault.Foreground(borderColor))
		}
		
		// Draw title if present
		if c.title != "" && width > 4 {
			titleColor := tcell.ColorWhite // Default title color
			title := c.title
			if len(title) > width-4 {
				title = title[:width-4] + "..."
			}
			tview.Print(screen, " "+title+" ", x+1, y-1, width-2, tview.AlignLeft, titleColor)
		}
	}
	
	// Draw content
	if c.content != nil {
		c.content.SetRect(x, y, width, height)
		c.content.Draw(screen)
	}
}

// Focus passes focus to the content
func (c *CustomBox) Focus(delegate func(p tview.Primitive)) {
	if c.content != nil {
		delegate(c.content)
	}
}

// HasFocus returns whether the content has focus
func (c *CustomBox) HasFocus() bool {
	if c.content != nil {
		return c.content.HasFocus()
	}
	return false
}

// InputHandler returns the handler for this primitive
func (c *CustomBox) InputHandler() func(event *tcell.EventKey, setFocus func(p tview.Primitive)) {
	return c.WrapInputHandler(func(event *tcell.EventKey, setFocus func(p tview.Primitive)) {
		if c.content != nil && c.content.HasFocus() {
			if handler := c.content.InputHandler(); handler != nil {
				handler(event, setFocus)
			}
		}
	})
}

// MouseHandler returns the mouse handler for this primitive
func (c *CustomBox) MouseHandler() func(action tview.MouseAction, event *tcell.EventMouse, setFocus func(p tview.Primitive)) (consumed bool, capture tview.Primitive) {
	return c.WrapMouseHandler(func(action tview.MouseAction, event *tcell.EventMouse, setFocus func(p tview.Primitive)) (consumed bool, capture tview.Primitive) {
		if c.content == nil {
			return false, nil
		}
		
		// Pass mouse events to content
		if handler := c.content.MouseHandler(); handler != nil {
			return handler(action, event, setFocus)
		}
		return false, nil
	})
}