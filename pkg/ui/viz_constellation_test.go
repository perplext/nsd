package ui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/perplext/nsd/pkg/netcap"
)

func TestNewConstellationVisualization(t *testing.T) {
	viz := NewConstellationVisualization()
	
	assert.NotNil(t, viz)
	assert.Equal(t, "Port Constellation", viz.GetName())
}

func TestConstellationVisualizationUpdate(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	viz := NewConstellationVisualization()
	
	// Should not panic
	assert.NotPanics(t, func() {
		viz.Update(monitor)
	})
}

func TestConstellationVisualizationGetMinSize(t *testing.T) {
	viz := NewConstellationVisualization()
	
	w, h := viz.GetMinSize()
	assert.Equal(t, 60, w)
	assert.Equal(t, 30, h)
}

func TestConstellationVisualizationSupportsFullscreen(t *testing.T) {
	viz := NewConstellationVisualization()
	
	assert.True(t, viz.SupportsFullscreen())
}

func TestConstellationVisualizationSetTheme(t *testing.T) {
	viz := NewConstellationVisualization()
	
	// Should not panic
	assert.NotPanics(t, func() {
		viz.SetTheme(Theme{})
	})
}