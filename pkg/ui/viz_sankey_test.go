package ui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/perplext/nsd/pkg/netcap"
)

func TestNewSankeyVisualization(t *testing.T) {
	viz := NewSankeyVisualization()
	
	assert.NotNil(t, viz)
	assert.Equal(t, "Network Flow Sankey", viz.GetName())
}

func TestSankeyVisualizationUpdate(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	viz := NewSankeyVisualization()
	
	// Should not panic
	assert.NotPanics(t, func() {
		viz.Update(monitor)
	})
}

func TestSankeyVisualizationGetMinSize(t *testing.T) {
	viz := NewSankeyVisualization()
	
	w, h := viz.GetMinSize()
	assert.Equal(t, 60, w)
	assert.Equal(t, 20, h)
}

func TestSankeyVisualizationSupportsFullscreen(t *testing.T) {
	viz := NewSankeyVisualization()
	
	assert.True(t, viz.SupportsFullscreen())
}

func TestSankeyVisualizationSetTheme(t *testing.T) {
	viz := NewSankeyVisualization()
	
	// Should not panic
	assert.NotPanics(t, func() {
		viz.SetTheme(Theme{})
	})
}