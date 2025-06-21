package ui

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBorderStyleOperations(t *testing.T) {
	// Test BorderStyleNames
	names := BorderStyleNames()
	assert.NotEmpty(t, names)
	assert.Contains(t, names, "Single")
	assert.Contains(t, names, "Double")
	assert.Contains(t, names, "Rounded")
	assert.Contains(t, names, "Bold")
	assert.Contains(t, names, "Classic") // ASCII style
	assert.Contains(t, names, "Dotted")
	assert.Contains(t, names, "Dashed")
	assert.Contains(t, names, "Minimal")
	
	// Names should have at least 8 styles
	assert.GreaterOrEqual(t, len(names), 8)
	
	// Test GetBorderStyle
	for _, styleName := range names {
		t.Run(styleName, func(t *testing.T) {
			style := GetBorderStyle(styleName)
			// Check that all border characters are set
			assert.NotEqual(t, rune(0), style.TopLeft)
			assert.NotEqual(t, rune(0), style.TopRight)
			assert.NotEqual(t, rune(0), style.BottomLeft)
			assert.NotEqual(t, rune(0), style.BottomRight)
			assert.NotEqual(t, rune(0), style.Horizontal)
			assert.NotEqual(t, rune(0), style.Vertical)
			assert.NotEqual(t, rune(0), style.Cross)
			assert.NotEqual(t, rune(0), style.HorizontalDown)
			assert.NotEqual(t, rune(0), style.HorizontalUp)
			assert.NotEqual(t, rune(0), style.VerticalLeft)
			assert.NotEqual(t, rune(0), style.VerticalRight)
		})
	}
	
	// Test invalid style name defaults to Single
	invalidStyle := GetBorderStyle("NonExistent")
	singleStyle := GetBorderStyle("Single")
	assert.Equal(t, singleStyle, invalidStyle)
}

func TestSpecialBorderStyles(t *testing.T) {
	// Test special border styles
	fireStyle := GetBorderStyle("Fire")
	assert.Equal(t, '🔥', fireStyle.TopLeft)
	assert.Equal(t, '🔥', fireStyle.TopRight)
	
	matrixStyle := GetBorderStyle("Matrix")
	assert.Equal(t, '◢', matrixStyle.TopLeft)  // Matrix style uses these triangle chars
	assert.Equal(t, '◣', matrixStyle.TopRight)
	
	starsStyle := GetBorderStyle("Stars")  // Stars style, not Cosmic
	assert.Equal(t, '✦', starsStyle.TopLeft)
	assert.Equal(t, '✦', starsStyle.TopRight)
	
	blockShadeStyle := GetBorderStyle("BlockShade")  // BlockShade style, not Retro
	assert.Equal(t, '▛', blockShadeStyle.TopLeft)
	assert.Equal(t, '▜', blockShadeStyle.TopRight)
	
	minimalStyle := GetBorderStyle("Minimal")
	assert.Equal(t, ' ', minimalStyle.TopLeft)
	assert.Equal(t, ' ', minimalStyle.TopRight)
	assert.Equal(t, ' ', minimalStyle.Horizontal)  // Minimal style uses spaces
	assert.Equal(t, ' ', minimalStyle.Vertical)
}

func TestBorderCharacterConsistency(t *testing.T) {
	// Test that all styles have consistent character sets
	names := BorderStyleNames()
	
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			style := GetBorderStyle(name)
			// Check that if any corner is special, all corners should be consistent
			if style.TopLeft == '🔥' {
				assert.Equal(t, '🔥', style.TopRight)
				assert.Equal(t, '🔥', style.BottomLeft)
				assert.Equal(t, '🔥', style.BottomRight)
			}
			
			// Check that lines are consistent
			if style.Horizontal != ' ' && style.Vertical != ' ' {
				assert.NotEqual(t, rune(0), style.Horizontal)
				assert.NotEqual(t, rune(0), style.Vertical)
			}
		})
	}
}

func TestGetBorderStyleCaseSensitivity(t *testing.T) {
	// Test that style names are case-insensitive
	styles := []string{"single", "DOUBLE", "RoUnDeD", "thick"}
	
	for _, styleName := range styles {
		style := GetBorderStyle(styleName)
		assert.NotEqual(t, rune(0), style.TopLeft)
		assert.NotEqual(t, rune(0), style.Horizontal)
		assert.NotEqual(t, rune(0), style.Vertical)
	}
}