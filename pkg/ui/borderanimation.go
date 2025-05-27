package ui

import (
	"github.com/gdamore/tcell/v2"
)

// BorderAnimation defines different animation types
type BorderAnimation int

const (
	AnimationNone BorderAnimation = iota
	AnimationRainbow
	AnimationPulse
	AnimationFire
	AnimationMatrix
	AnimationWave
	AnimationSparkle
)

// AnimationNames maps animation names to types
var AnimationNames = []string{
	"None",
	"Rainbow",
	"Pulse",
	"Fire",
	"Matrix",
	"Wave",
	"Sparkle",
}

// GetAnimatedBorderColor returns the color for animated borders
func GetAnimatedBorderColor(baseColor tcell.Color, animation string, frame int) tcell.Color {
	switch animation {
	case "Rainbow":
		return getRainbowColor(frame)
	case "Pulse":
		return getPulseColor(baseColor, frame)
	case "Fire":
		return getFireColor(frame)
	case "Matrix":
		return getMatrixColor(frame)
	case "Wave":
		return getWaveColor(baseColor, frame)
	case "Sparkle":
		return getSparkleColor(baseColor, frame)
	default:
		return baseColor
	}
}

// getRainbowColor cycles through rainbow colors
func getRainbowColor(frame int) tcell.Color {
	colors := []tcell.Color{
		tcell.NewRGBColor(255, 0, 0),     // Red
		tcell.NewRGBColor(255, 127, 0),   // Orange
		tcell.NewRGBColor(255, 255, 0),   // Yellow
		tcell.NewRGBColor(0, 255, 0),     // Green
		tcell.NewRGBColor(0, 0, 255),     // Blue
		tcell.NewRGBColor(75, 0, 130),    // Indigo
		tcell.NewRGBColor(148, 0, 211),   // Violet
	}
	return colors[frame%len(colors)]
}

// getPulseColor creates a pulsing effect
func getPulseColor(baseColor tcell.Color, frame int) tcell.Color {
	// Create a sine wave effect
	intensity := (frame % 20) 
	if intensity > 10 {
		intensity = 20 - intensity
	}
	
	r, g, b := baseColor.RGB()
	factor := float64(intensity) / 10.0
	
	// Brighten the color based on the pulse
	newR := int32(float64(r) * (0.5 + 0.5*factor))
	newG := int32(float64(g) * (0.5 + 0.5*factor))
	newB := int32(float64(b) * (0.5 + 0.5*factor))
	
	// Clamp values
	if newR > 255 { newR = 255 }
	if newG > 255 { newG = 255 }
	if newB > 255 { newB = 255 }
	
	return tcell.NewRGBColor(newR, newG, newB)
}

// getFireColor creates fire-like colors
func getFireColor(frame int) tcell.Color {
	colors := []tcell.Color{
		tcell.NewRGBColor(255, 0, 0),     // Red
		tcell.NewRGBColor(255, 69, 0),    // Orange-red
		tcell.NewRGBColor(255, 140, 0),   // Dark orange
		tcell.NewRGBColor(255, 215, 0),   // Gold
		tcell.NewRGBColor(255, 255, 0),   // Yellow
	}
	// Add some randomness to fire effect
	idx := (frame / 2) % len(colors)
	return colors[idx]
}

// getMatrixColor creates matrix-like green variations
func getMatrixColor(frame int) tcell.Color {
	intensity := 100 + (frame*10)%155
	return tcell.NewRGBColor(0, int32(intensity), 0)
}

// getWaveColor creates a wave effect
func getWaveColor(baseColor tcell.Color, frame int) tcell.Color {
	r, g, b := baseColor.RGB()
	
	// Create wave effect by modifying different channels at different rates
	waveR := int32(float64(r) * (0.8 + 0.2*sin(float64(frame)*0.1)))
	waveG := int32(float64(g) * (0.8 + 0.2*sin(float64(frame)*0.15)))
	waveB := int32(float64(b) * (0.8 + 0.2*sin(float64(frame)*0.2)))
	
	return tcell.NewRGBColor(waveR, waveG, waveB)
}

// getSparkleColor creates random sparkles
func getSparkleColor(baseColor tcell.Color, frame int) tcell.Color {
	// Every few frames, create a bright sparkle
	if frame%7 == 0 {
		return tcell.ColorWhite
	}
	return baseColor
}

// sin approximation for wave effects
func sin(x float64) float64 {
	// Simple sine approximation
	x = x - float64(int(x/(2*3.14159)))*(2*3.14159)
	if x < 0 {
		x = -x
	}
	if x > 3.14159 {
		x = 2*3.14159 - x
	}
	// Taylor series approximation
	return x - (x*x*x)/6 + (x*x*x*x*x)/120
}

// GetAnimatedBorderChar returns animated border characters for certain styles
func GetAnimatedBorderChar(style BorderChars, position string, frame int) rune {
	// For fire animation, cycle through different fire characters
	if style.TopLeft == '🔥' {
		fireChars := []rune{'🔥', '🔥', '🔥', '🔥'}
		return fireChars[frame%len(fireChars)]
	}
	
	// For sparkle/star animations
	if style.TopLeft == '✦' {
		starChars := []rune{'✦', '✧', '✶', '✷', '✵'}
		return starChars[frame%len(starChars)]
	}
	
	// Default: return the appropriate character for the position
	switch position {
	case "TopLeft":
		return style.TopLeft
	case "TopRight":
		return style.TopRight
	case "BottomLeft":
		return style.BottomLeft
	case "BottomRight":
		return style.BottomRight
	case "Horizontal":
		return style.Horizontal
	case "Vertical":
		return style.Vertical
	case "Cross":
		return style.Cross
	case "HorizontalDown":
		return style.HorizontalDown
	case "HorizontalUp":
		return style.HorizontalUp
	case "VerticalLeft":
		return style.VerticalLeft
	case "VerticalRight":
		return style.VerticalRight
	default:
		return style.Cross
	}
}