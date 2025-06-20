package ui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/perplext/nsd/pkg/netcap"
)

func TestNewSunburstVisualization(t *testing.T) {
	viz := NewSunburstVisualization()
	
	assert.NotNil(t, viz)
	assert.Equal(t, "Connection Sunburst", viz.GetName())
}

func TestSunburstVisualizationUpdate(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	viz := NewSunburstVisualization()
	
	// Should not panic
	assert.NotPanics(t, func() {
		viz.Update(monitor)
	})
}

func TestSunburstVisualizationGetMinSize(t *testing.T) {
	viz := NewSunburstVisualization()
	
	w, h := viz.GetMinSize()
	assert.Equal(t, 60, w)
	assert.Equal(t, 35, h)
}

func TestSunburstVisualizationSupportsFullscreen(t *testing.T) {
	viz := NewSunburstVisualization()
	
	assert.True(t, viz.SupportsFullscreen())
}

func TestSunburstVisualizationSetTheme(t *testing.T) {
	viz := NewSunburstVisualization()
	
	// Should not panic
	assert.NotPanics(t, func() {
		viz.SetTheme(Theme{})
	})
}