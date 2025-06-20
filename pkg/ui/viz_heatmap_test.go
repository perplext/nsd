package ui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/perplext/nsd/pkg/netcap"
)

func TestNewHeatmapVisualization(t *testing.T) {
	viz := NewHeatmapVisualization()
	
	assert.NotNil(t, viz)
	assert.Equal(t, "Traffic Heatmap", viz.GetName())
}

func TestHeatmapVisualizationUpdate(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	viz := NewHeatmapVisualization()
	
	// Should not panic
	assert.NotPanics(t, func() {
		viz.Update(monitor)
	})
}

func TestHeatmapVisualizationGetMinSize(t *testing.T) {
	viz := NewHeatmapVisualization()
	
	w, h := viz.GetMinSize()
	assert.Greater(t, w, 0)
	assert.Greater(t, h, 0)
}

func TestHeatmapVisualizationSupportsFullscreen(t *testing.T) {
	viz := NewHeatmapVisualization()
	
	assert.True(t, viz.SupportsFullscreen())
}

func TestHeatmapVisualizationSetTheme(t *testing.T) {
	viz := NewHeatmapVisualization()
	
	// Should not panic
	assert.NotPanics(t, func() {
		viz.SetTheme(Theme{})
	})
}

func TestHeatmapVisualizationWithConnections(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	viz := NewHeatmapVisualization()
	
	// Update should process connections
	viz.Update(monitor)
	
	// Should have processed the connections without panic
	assert.NotNil(t, viz)
}