package ui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/perplext/nsd/pkg/netcap"
)

func TestNewWeatherMapVisualization(t *testing.T) {
	viz := NewWeatherMapVisualization()
	
	assert.NotNil(t, viz)
	assert.Equal(t, "Network Weather", viz.GetName())
}

func TestWeatherMapVisualizationUpdate(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	viz := NewWeatherMapVisualization()
	
	// Should not panic
	assert.NotPanics(t, func() {
		viz.Update(monitor)
	})
}

func TestWeatherMapVisualizationGetMinSize(t *testing.T) {
	viz := NewWeatherMapVisualization()
	
	w, h := viz.GetMinSize()
	assert.Equal(t, 40, w)
	assert.Equal(t, 25, h)
}

func TestWeatherMapVisualizationSupportsFullscreen(t *testing.T) {
	viz := NewWeatherMapVisualization()
	
	assert.True(t, viz.SupportsFullscreen())
}

func TestWeatherMapVisualizationSetTheme(t *testing.T) {
	viz := NewWeatherMapVisualization()
	
	// Should not panic
	assert.NotPanics(t, func() {
		viz.SetTheme(Theme{})
	})
}