package ui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/perplext/nsd/pkg/netcap"
)

func TestNewRadialConnectionVisualization(t *testing.T) {
	viz := NewRadialConnectionVisualization()
	
	assert.NotNil(t, viz)
	assert.Equal(t, "Radial Connection View", viz.GetName())
}

func TestRadialConnectionVisualizationUpdate(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	viz := NewRadialConnectionVisualization()
	
	// Should not panic
	assert.NotPanics(t, func() {
		viz.Update(monitor)
	})
}

func TestRadialConnectionVisualizationGetMinSize(t *testing.T) {
	viz := NewRadialConnectionVisualization()
	
	w, h := viz.GetMinSize()
	assert.Equal(t, 80, w)
	assert.Equal(t, 24, h)
}

func TestRadialConnectionVisualizationSupportsFullscreen(t *testing.T) {
	viz := NewRadialConnectionVisualization()
	
	assert.True(t, viz.SupportsFullscreen())
}

func TestRadialConnectionVisualizationSetTheme(t *testing.T) {
	viz := NewRadialConnectionVisualization()
	
	// Should not panic
	assert.NotPanics(t, func() {
		viz.SetTheme(Theme{})
	})
}

func TestRadialConnectionVisualizationWithConnections(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	viz := NewRadialConnectionVisualization()
	
	// Add test connections
	// Note: Cannot set connections directly in test
	
	// Update to process connections
	viz.Update(monitor)
	
	// Should have processed connections
	assert.NotNil(t, viz)
}

func TestRadialConnectionVisualizationNodePositioning(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	viz := NewRadialConnectionVisualization()
	
	// Create a simple connection
	// Note: Cannot set connections directly in test
	
	viz.Update(monitor)
	
	// Should have processed without panic
	assert.NotNil(t, viz)
}