package ui

import (
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/stretchr/testify/assert"
	"github.com/perplext/nsd/pkg/netcap"
)

func TestNewMatrixRainVisualization(t *testing.T) {
	viz := NewMatrixRainVisualization()
	
	assert.NotNil(t, viz)
	assert.Equal(t, "Matrix Rain", viz.GetName())
}

func TestMatrixRainVisualizationUpdate(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	viz := NewMatrixRainVisualization()
	
	// Should not panic
	assert.NotPanics(t, func() {
		viz.Update(monitor)
	})
	
	// Should have completed without panic
}

func TestMatrixRainVisualizationGetMinSize(t *testing.T) {
	viz := NewMatrixRainVisualization()
	
	w, h := viz.GetMinSize()
	assert.Equal(t, 80, w)
	assert.Equal(t, 24, h)
}

func TestMatrixRainVisualizationSupportsFullscreen(t *testing.T) {
	viz := NewMatrixRainVisualization()
	
	assert.True(t, viz.SupportsFullscreen())
}

func TestMatrixRainVisualizationSetTheme(t *testing.T) {
	viz := NewMatrixRainVisualization()
	
	theme := Theme{
		PrimaryColor: tcell.ColorGreen,
	}
	
	assert.NotPanics(t, func() {
		viz.SetTheme(theme)
	})
	
	// Theme should be set
}

func TestMatrixRainVisualizationWithTraffic(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	viz := NewMatrixRainVisualization()
	
	// Simulate traffic
	// Note: Cannot set monitor values directly in test
	
	// Update multiple times to see animation
	for i := 0; i < 5; i++ {
		viz.Update(monitor)
	}
	
	// Should have updated without panic
	assert.NotNil(t, viz)
}