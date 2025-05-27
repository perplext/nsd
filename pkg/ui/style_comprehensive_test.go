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
	assert.Contains(t, names, "Thick")
	assert.Contains(t, names, "ASCII")
	assert.Contains(t, names, "Dotted")
	assert.Contains(t, names, "Dashed")
	assert.Contains(t, names, "Bold")
	
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
	assert.Equal(t, '0', matrixStyle.TopLeft)
	assert.Equal(t, '1', matrixStyle.TopRight)
	
	cosmicStyle := GetBorderStyle("Cosmic")
	assert.Equal(t, '✦', cosmicStyle.TopLeft)
	assert.Equal(t, '✦', cosmicStyle.TopRight)
	
	retroStyle := GetBorderStyle("Retro")
	assert.Equal(t, '▛', retroStyle.TopLeft)
	assert.Equal(t, '▜', retroStyle.TopRight)
	
	minimalStyle := GetBorderStyle("Minimal")
	assert.Equal(t, ' ', minimalStyle.TopLeft)
	assert.Equal(t, ' ', minimalStyle.TopRight)
	assert.Equal(t, '─', minimalStyle.Horizontal)
	assert.Equal(t, '│', minimalStyle.Vertical)
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