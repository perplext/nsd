package ui

// StyleDefinition encapsulates border characters for UI styles.
type StyleDefinition struct {
	BorderTL     rune // top-left corner
	BorderTR     rune // top-right corner
	BorderBL     rune // bottom-left corner
	BorderBR     rune // bottom-right corner
	BorderH      rune // horizontal line
	BorderV      rune // vertical line
}

// Styles holds predefined UI styles.
var Styles = map[string]StyleDefinition{
	"Standard": {
		BorderTL: '+',
		BorderTR: '+',
		BorderBL: '+',
		BorderBR: '+',
		BorderH:  '-',
		BorderV:  '|',
	},
	"btop": {
		BorderTL: '╭',
		BorderTR: '╮',
		BorderBL: '╰',
		BorderBR: '╯',
		BorderH:  '─',
		BorderV:  '│',
	},
}
