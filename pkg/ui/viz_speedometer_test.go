package ui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/perplext/nsd/pkg/netcap"
)

func TestNewSpeedometerVisualization(t *testing.T) {
	viz := NewSpeedometerVisualization()
	
	assert.NotNil(t, viz)
	assert.Equal(t, "Bandwidth Speedometer", viz.GetName())
}

func TestSpeedometerVisualizationUpdate(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	viz := NewSpeedometerVisualization()
	
	// Should not panic
	assert.NotPanics(t, func() {
		viz.Update(monitor)
	})
}

func TestSpeedometerVisualizationGetMinSize(t *testing.T) {
	viz := NewSpeedometerVisualization()
	
	w, h := viz.GetMinSize()
	assert.Equal(t, 45, w)
	assert.Equal(t, 20, h)
}

func TestSpeedometerVisualizationSupportsFullscreen(t *testing.T) {
	viz := NewSpeedometerVisualization()
	
	assert.True(t, viz.SupportsFullscreen())
}

func TestSpeedometerVisualizationSetTheme(t *testing.T) {
	viz := NewSpeedometerVisualization()
	
	// Should not panic
	assert.NotPanics(t, func() {
		viz.SetTheme(Theme{})
	})
}