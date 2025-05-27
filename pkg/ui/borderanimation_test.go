package ui

import (
	"math"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/stretchr/testify/assert"
)

func TestGetAnimatedBorderColor(t *testing.T) {
	baseColor := tcell.ColorWhite
	animations := []string{
		"Rainbow", "Pulse", "Fire", "Matrix", "Wave", "Sparkle", "None",
	}
	for _, anim := range animations {
		color := GetAnimatedBorderColor(baseColor, anim, 0)
		assert.NotEqual(t, tcell.ColorDefault, color)
	}
}

func TestGetRainbowColor(t *testing.T) {
	color1 := getRainbowColor(0)
	color2 := getRainbowColor(1)
	color3 := getRainbowColor(2)

	assert.NotEqual(t, color1, color2)
	assert.NotEqual(t, color2, color3)

	// Test cycling
	color7 := getRainbowColor(7)
	color0 := getRainbowColor(0)
	assert.Equal(t, color0, color7)
}

func TestGetPulseColor(t *testing.T) {
	baseColor := tcell.ColorBlue
	color1 := getPulseColor(baseColor, 0)
	color2 := getPulseColor(baseColor, 10)
	color3 := getPulseColor(baseColor, 20)

	assert.NotEqual(t, tcell.ColorDefault, color1)
	assert.NotEqual(t, tcell.ColorDefault, color2)
	assert.NotEqual(t, tcell.ColorDefault, color3)

	// Test pulse cycle
	for i := 0; i < 40; i++ {
		color := getPulseColor(baseColor, i)
		assert.NotEqual(t, tcell.ColorDefault, color)
	}
}

func TestGetFireColor(t *testing.T) {
	color1 := getFireColor(0)
	color2 := getFireColor(2)
	color3 := getFireColor(4)

	assert.NotEqual(t, tcell.ColorDefault, color1)
	assert.NotEqual(t, tcell.ColorDefault, color2)
	assert.NotEqual(t, tcell.ColorDefault, color3)

	// Fire should cycle through colors
	for i := 0; i < 10; i++ {
		color := getFireColor(i)
		assert.NotEqual(t, tcell.ColorDefault, color)
	}
}

func TestGetMatrixColor(t *testing.T) {
	color1 := getMatrixColor(0)
	color2 := getMatrixColor(10)
	color3 := getMatrixColor(20)

	assert.NotEqual(t, tcell.ColorDefault, color1)
	assert.NotEqual(t, tcell.ColorDefault, color2)
	assert.NotEqual(t, tcell.ColorDefault, color3)

	// Matrix should be green-ish variations
	for i := 0; i < 50; i++ {
		color := getMatrixColor(i)
		assert.NotEqual(t, tcell.ColorDefault, color)
	}
}

func TestGetWaveColor(t *testing.T) {
	baseColor := tcell.ColorRed
	color1 := getWaveColor(baseColor, 0)
	color2 := getWaveColor(baseColor, 30)
	color3 := getWaveColor(baseColor, 60)

	assert.NotEqual(t, tcell.ColorDefault, color1)
	assert.NotEqual(t, tcell.ColorDefault, color2)
	assert.NotEqual(t, tcell.ColorDefault, color3)

	// Test wave progression
	for i := 0; i < 100; i++ {
		color := getWaveColor(baseColor, i)
		assert.NotEqual(t, tcell.ColorDefault, color)
	}
}

func TestGetSparkleColor(t *testing.T) {
	baseColor := tcell.ColorYellow
	
	// Test sparkle effect - should sometimes return white (sparkle) or base color
	for i := 0; i < 20; i++ {
		color := getSparkleColor(baseColor, i)
		assert.NotEqual(t, tcell.ColorDefault, color)
		// Color should be either base color or white (sparkle)
		assert.True(t, color == baseColor || color == tcell.ColorWhite)
	}
}

func TestSinFunction(t *testing.T) {
	// Test the custom sin function - it's a simple approximation
	result1 := sin(0.0)
	result2 := sin(1.0) // Test with 1 radian
	result3 := sin(2.0) // Test with 2 radians

	// Just test that the function returns valid numbers and doesn't panic
	assert.False(t, math.IsNaN(float64(result1)))
	assert.False(t, math.IsNaN(float64(result2)))
	assert.False(t, math.IsNaN(float64(result3)))
	
	// Test that sin(0) is close to 0
	assert.InDelta(t, 0.0, result1, 0.1)
}

func TestGetAnimatedBorderChar(t *testing.T) {
	style := BorderChars{
		TopLeft:     '┌',
		TopRight:    '┐',
		BottomLeft:  '└',
		BottomRight: '┘',
		Horizontal:  '─',
		Vertical:    '│',
		Cross:       '┼',
	}

	positions := []string{
		"TopLeft", "TopRight", "BottomLeft", "BottomRight",
		"Horizontal", "Vertical", "Cross",
	}

	for _, pos := range positions {
		char := GetAnimatedBorderChar(style, pos, 0)
		assert.NotEqual(t, rune(0), char)
	}
}

func TestAnimationNamesConstant(t *testing.T) {
	// Test that AnimationNames slice exists and has expected values
	assert.NotNil(t, AnimationNames)
	assert.Contains(t, AnimationNames, "Rainbow")
	assert.Contains(t, AnimationNames, "Pulse")
	assert.Contains(t, AnimationNames, "Fire")
	assert.Contains(t, AnimationNames, "Matrix")
	assert.Contains(t, AnimationNames, "Wave")
	assert.Contains(t, AnimationNames, "Sparkle")
	assert.Contains(t, AnimationNames, "None")
}

func TestBorderAnimationConstants(t *testing.T) {
	// Test that BorderAnimation constants exist
	assert.Equal(t, BorderAnimation(0), AnimationNone)
	assert.Equal(t, BorderAnimation(1), AnimationRainbow)
	assert.Equal(t, BorderAnimation(2), AnimationPulse)
	assert.Equal(t, BorderAnimation(3), AnimationFire)
	assert.Equal(t, BorderAnimation(4), AnimationMatrix)
	assert.Equal(t, BorderAnimation(5), AnimationWave)
	assert.Equal(t, BorderAnimation(6), AnimationSparkle)
}

func TestAnimationColorConsistency(t *testing.T) {
	// Test that same inputs produce same outputs
	baseColor := tcell.NewRGBColor(0, 255, 255) // Cyan
	animation := "Wave"
	frame := 42

	color1 := GetAnimatedBorderColor(baseColor, animation, frame)
	color2 := GetAnimatedBorderColor(baseColor, animation, frame)

	assert.Equal(t, color1, color2)
}

func TestAnimationEdgeCases(t *testing.T) {
	baseColor := tcell.ColorWhite
	
	// Test with unknown animation
	color := GetAnimatedBorderColor(baseColor, "UnknownAnimation", 0)
	assert.Equal(t, baseColor, color) // Should return base color

	// Test with very large frame numbers
	color = GetAnimatedBorderColor(baseColor, "Rainbow", 999999)
	assert.NotEqual(t, tcell.ColorDefault, color)

	// Test with negative frame numbers
	color = GetAnimatedBorderColor(baseColor, "Pulse", -100)
	assert.NotEqual(t, tcell.ColorDefault, color)
}