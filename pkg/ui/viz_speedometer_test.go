package ui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/user/nsd/pkg/netcap"
)

func TestNewSpeedometerVisualization(t *testing.T) {
	viz := NewSpeedometerVisualization()
	
	assert.NotNil(t, viz)
	assert.Equal(t, "Network Speedometer", viz.GetName())
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
	assert.Equal(t, 40, w)
	assert.Equal(t, 20, h)
}

func TestSpeedometerVisualizationSupportsFullscreen(t *testing.T) {
	viz := NewSpeedometerVisualization()
	
	assert.False(t, viz.SupportsFullscreen())
}

func TestSpeedometerVisualizationSetTheme(t *testing.T) {
	viz := NewSpeedometerVisualization()
	
	// Should not panic
	assert.NotPanics(t, func() {
		viz.SetTheme(Theme{})
	})
}