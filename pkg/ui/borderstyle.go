package ui

import "sort"

// BorderStyle represents different border drawing styles
type BorderStyle int

const (
	BorderStyleSingle BorderStyle = iota
	BorderStyleDouble
	BorderStyleRounded
	BorderStyleBold
	BorderStyleDashed
	BorderStyleDotted
	BorderStyleClassic // ASCII style
	BorderStyleMinimal
	BorderStyleBBS     // Retro BBS style
	BorderStyleNone
)

// BorderChars defines the characters used for drawing borders
type BorderChars struct {
	TopLeft     rune
	TopRight    rune
	BottomLeft  rune
	BottomRight rune
	Horizontal  rune
	Vertical    rune
	Cross       rune
	HorizontalDown rune
	HorizontalUp   rune
	VerticalLeft   rune
	VerticalRight  rune
}

// BorderStyles maps style names to their character sets
var BorderStyles = map[string]BorderChars{
	"Single": {
		TopLeft:     '┌',
		TopRight:    '┐',
		BottomLeft:  '└',
		BottomRight: '┘',
		Horizontal:  '─',
		Vertical:    '│',
		Cross:       '┼',
		HorizontalDown: '┬',
		HorizontalUp:   '┴',
		VerticalLeft:   '┤',
		VerticalRight:  '├',
	},
	"Double": {
		TopLeft:     '╔',
		TopRight:    '╗',
		BottomLeft:  '╚',
		BottomRight: '╝',
		Horizontal:  '═',
		Vertical:    '║',
		Cross:       '╬',
		HorizontalDown: '╦',
		HorizontalUp:   '╩',
		VerticalLeft:   '╣',
		VerticalRight:  '╠',
	},
	"Rounded": {
		TopLeft:     '╭',
		TopRight:    '╮',
		BottomLeft:  '╰',
		BottomRight: '╯',
		Horizontal:  '─',
		Vertical:    '│',
		Cross:       '┼',
		HorizontalDown: '┬',
		HorizontalUp:   '┴',
		VerticalLeft:   '┤',
		VerticalRight:  '├',
	},
	"Bold": {
		TopLeft:     '┏',
		TopRight:    '┓',
		BottomLeft:  '┗',
		BottomRight: '┛',
		Horizontal:  '━',
		Vertical:    '┃',
		Cross:       '╋',
		HorizontalDown: '┳',
		HorizontalUp:   '┻',
		VerticalLeft:   '┫',
		VerticalRight:  '┣',
	},
	"Dashed": {
		TopLeft:     '┌',
		TopRight:    '┐',
		BottomLeft:  '└',
		BottomRight: '┘',
		Horizontal:  '╌',
		Vertical:    '╎',
		Cross:       '┼',
		HorizontalDown: '┬',
		HorizontalUp:   '┴',
		VerticalLeft:   '┤',
		VerticalRight:  '├',
	},
	"Dotted": {
		TopLeft:     '⡏',
		TopRight:    '⢹',
		BottomLeft:  '⣇',
		BottomRight: '⣸',
		Horizontal:  '⠉',
		Vertical:    '⡇',
		Cross:       '⡇',
		HorizontalDown: '⠉',
		HorizontalUp:   '⠉',
		VerticalLeft:   '⡇',
		VerticalRight:  '⡇',
	},
	"Classic": {
		TopLeft:     '+',
		TopRight:    '+',
		BottomLeft:  '+',
		BottomRight: '+',
		Horizontal:  '-',
		Vertical:    '|',
		Cross:       '+',
		HorizontalDown: '+',
		HorizontalUp:   '+',
		VerticalLeft:   '+',
		VerticalRight:  '+',
	},
	"Minimal": {
		TopLeft:     ' ',
		TopRight:    ' ',
		BottomLeft:  ' ',
		BottomRight: ' ',
		Horizontal:  ' ',
		Vertical:    ' ',
		Cross:       ' ',
		HorizontalDown: ' ',
		HorizontalUp:   ' ',
		VerticalLeft:   ' ',
		VerticalRight:  ' ',
	},
	"BBS": {
		TopLeft:     '╓',
		TopRight:    '╖',
		BottomLeft:  '╙',
		BottomRight: '╜',
		Horizontal:  '─',
		Vertical:    '║',
		Cross:       '╫',
		HorizontalDown: '╥',
		HorizontalUp:   '╨',
		VerticalLeft:   '╢',
		VerticalRight:  '╟',
	},
	"BlockShade": {
		TopLeft:     '▛',
		TopRight:    '▜',
		BottomLeft:  '▙',
		BottomRight: '▟',
		Horizontal:  '▀',
		Vertical:    '▌',
		Cross:       '█',
		HorizontalDown: '▀',
		HorizontalUp:   '▄',
		VerticalLeft:   '▐',
		VerticalRight:  '▌',
	},
	"DoubleInside": {
		TopLeft:     '╒',
		TopRight:    '╕',
		BottomLeft:  '╘',
		BottomRight: '╛',
		Horizontal:  '═',
		Vertical:    '│',
		Cross:       '╪',
		HorizontalDown: '╤',
		HorizontalUp:   '╧',
		VerticalLeft:   '╡',
		VerticalRight:  '╞',
	},
	"Stars": {
		TopLeft:     '✦',
		TopRight:    '✦',
		BottomLeft:  '✦',
		BottomRight: '✦',
		Horizontal:  '═',
		Vertical:    '║',
		Cross:       '✦',
		HorizontalDown: '✦',
		HorizontalUp:   '✦',
		VerticalLeft:   '✦',
		VerticalRight:  '✦',
	},
	"Hearts": {
		TopLeft:     '♥',
		TopRight:    '♥',
		BottomLeft:  '♥',
		BottomRight: '♥',
		Horizontal:  '─',
		Vertical:    '│',
		Cross:       '♥',
		HorizontalDown: '♥',
		HorizontalUp:   '♥',
		VerticalLeft:   '♥',
		VerticalRight:  '♥',
	},
	"Arrows": {
		TopLeft:     '↖',
		TopRight:    '↗',
		BottomLeft:  '↙',
		BottomRight: '↘',
		Horizontal:  '↔',
		Vertical:    '↕',
		Cross:       '✚',
		HorizontalDown: '↓',
		HorizontalUp:   '↑',
		VerticalLeft:   '←',
		VerticalRight:  '→',
	},
	"Fire": {
		TopLeft:     '🔥',
		TopRight:    '🔥',
		BottomLeft:  '🔥',
		BottomRight: '🔥',
		Horizontal:  '═',
		Vertical:    '║',
		Cross:       '🔥',
		HorizontalDown: '🔥',
		HorizontalUp:   '🔥',
		VerticalLeft:   '🔥',
		VerticalRight:  '🔥',
	},
	"Tech": {
		TopLeft:     '⚡',
		TopRight:    '⚡',
		BottomLeft:  '⚡',
		BottomRight: '⚡',
		Horizontal:  '━',
		Vertical:    '┃',
		Cross:       '⚡',
		HorizontalDown: '⚡',
		HorizontalUp:   '⚡',
		VerticalLeft:   '⚡',
		VerticalRight:  '⚡',
	},
	"Matrix": {
		TopLeft:     '◢',
		TopRight:    '◣',
		BottomLeft:  '◥',
		BottomRight: '◤',
		Horizontal:  '▬',
		Vertical:    '▮',
		Cross:       '◆',
		HorizontalDown: '▼',
		HorizontalUp:   '▲',
		VerticalLeft:   '◀',
		VerticalRight:  '▶',
	},
	"Dots": {
		TopLeft:     '●',
		TopRight:    '●',
		BottomLeft:  '●',
		BottomRight: '●',
		Horizontal:  '·',
		Vertical:    '¦',
		Cross:       '●',
		HorizontalDown: '●',
		HorizontalUp:   '●',
		VerticalLeft:   '●',
		VerticalRight:  '●',
	},
	"Pipes": {
		TopLeft:     '╱',
		TopRight:    '╲',
		BottomLeft:  '╲',
		BottomRight: '╱',
		Horizontal:  '⎯',
		Vertical:    '⎪',
		Cross:       '╳',
		HorizontalDown: '⎬',
		HorizontalUp:   '⎫',
		VerticalLeft:   '⎨',
		VerticalRight:  '⎬',
	},
	"Vintage": {
		TopLeft:     '◊',
		TopRight:    '◊',
		BottomLeft:  '◊',
		BottomRight: '◊',
		Horizontal:  '~',
		Vertical:    '¦',
		Cross:       '◊',
		HorizontalDown: '◊',
		HorizontalUp:   '◊',
		VerticalLeft:   '◊',
		VerticalRight:  '◊',
	},
}

// GetBorderStyle returns the border characters for a given style name
func GetBorderStyle(styleName string) BorderChars {
	if style, ok := BorderStyles[styleName]; ok {
		return style
	}
	// Default to single style
	return BorderStyles["Single"]
}

// BorderStyleNames returns all available border style names
func BorderStyleNames() []string {
	names := make([]string, 0, len(BorderStyles))
	for name := range BorderStyles {
		names = append(names, name)
	}
	// Sort for consistent ordering
	sort.Strings(names)
	return names
}