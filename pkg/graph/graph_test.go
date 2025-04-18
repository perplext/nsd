package graph

import (
	"testing"
	"github.com/gdamore/tcell/v2"
)

func TestShadeBlock(t *testing.T) {
	tests := []struct {
		ratio float64
		want  rune
	}{
		{0.0, '·'},
		{0.05, '·'},
		{0.1, '░'},
		{0.2, '░'},
		{0.3, '▒'},
		{0.5, '▒'},
		{0.6, '▓'},
		{0.8, '▓'},
		{0.9, '█'},
		{1.0, '█'},
	}
	for _, tt := range tests {
		got := ShadeBlock(tt.ratio)
		if got != tt.want {
			t.Errorf("ShadeBlock(%v) = %q; want %q", tt.ratio, got, tt.want)
		}
	}
}

func TestColorToHex(t *testing.T) {
	tests := []struct {
		color tcell.Color
		want  string
	}{
		{tcell.ColorRed, "#ff0000"},
		{tcell.ColorGreen, "#00ff00"},
		{tcell.ColorBlue, "#0000ff"},
		{tcell.ColorWhite, "#ffffff"},
		{tcell.ColorBlack, "#000000"},
	}
	for _, tt := range tests {
		got := ColorToHex(tt.color)
		if got != tt.want {
			t.Errorf("ColorToHex(%v) = %q; want %q", tt.color, got, tt.want)
		}
	}
}
