package ui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/user/nsd/pkg/netcap"
)

func TestNewConnectionLifetimeVisualization(t *testing.T) {
	viz := NewConnectionLifetimeVisualization()
	
	assert.NotNil(t, viz)
	assert.Equal(t, "Connection Lifetime", viz.GetName())
}

func TestConnectionLifetimeVisualizationUpdate(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	viz := NewConnectionLifetimeVisualization()
	
	// Should not panic
	assert.NotPanics(t, func() {
		viz.Update(monitor)
	})
}

func TestConnectionLifetimeVisualizationGetMinSize(t *testing.T) {
	viz := NewConnectionLifetimeVisualization()
	
	w, h := viz.GetMinSize()
	assert.Equal(t, 60, w)
	assert.Equal(t, 20, h)
}

func TestConnectionLifetimeVisualizationSupportsFullscreen(t *testing.T) {
	viz := NewConnectionLifetimeVisualization()
	
	assert.False(t, viz.SupportsFullscreen())
}

func TestConnectionLifetimeVisualizationSetTheme(t *testing.T) {
	viz := NewConnectionLifetimeVisualization()
	
	// Should not panic
	assert.NotPanics(t, func() {
		viz.SetTheme(Theme{})
	})
}