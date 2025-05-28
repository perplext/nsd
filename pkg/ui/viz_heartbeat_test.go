package ui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/perplext/nsd/pkg/netcap"
)

func TestNewHeartbeatVisualization(t *testing.T) {
	viz := NewHeartbeatVisualization()
	
	assert.NotNil(t, viz)
	assert.Equal(t, "Network Heartbeat", viz.GetName())
}

func TestHeartbeatVisualizationUpdate(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	viz := NewHeartbeatVisualization()
	
	// Should not panic
	assert.NotPanics(t, func() {
		viz.Update(monitor)
	})
}

func TestHeartbeatVisualizationGetMinSize(t *testing.T) {
	viz := NewHeartbeatVisualization()
	
	w, h := viz.GetMinSize()
	assert.Greater(t, w, 0)
	assert.Greater(t, h, 0)
}

func TestHeartbeatVisualizationSupportsFullscreen(t *testing.T) {
	viz := NewHeartbeatVisualization()
	
	// Most visualizations don't support fullscreen
	assert.False(t, viz.SupportsFullscreen())
}

func TestHeartbeatVisualizationSetTheme(t *testing.T) {
	viz := NewHeartbeatVisualization()
	
	// Should not panic
	assert.NotPanics(t, func() {
		viz.SetTheme(Theme{})
	})
}