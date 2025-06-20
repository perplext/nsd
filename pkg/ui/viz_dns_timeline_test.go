package ui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/perplext/nsd/pkg/netcap"
)

func TestNewDNSTimelineVisualization(t *testing.T) {
	viz := NewDNSTimelineVisualization()
	
	assert.NotNil(t, viz)
	assert.Equal(t, "DNS Timeline", viz.GetName())
}

func TestDNSTimelineVisualizationUpdate(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	viz := NewDNSTimelineVisualization()
	
	// Should not panic
	assert.NotPanics(t, func() {
		viz.Update(monitor)
	})
}

func TestDNSTimelineVisualizationGetMinSize(t *testing.T) {
	viz := NewDNSTimelineVisualization()
	
	w, h := viz.GetMinSize()
	assert.Equal(t, 70, w)
	assert.Equal(t, 30, h)
}

func TestDNSTimelineVisualizationSupportsFullscreen(t *testing.T) {
	viz := NewDNSTimelineVisualization()
	
	assert.True(t, viz.SupportsFullscreen())
}

func TestDNSTimelineVisualizationSetTheme(t *testing.T) {
	viz := NewDNSTimelineVisualization()
	
	// Should not panic
	assert.NotPanics(t, func() {
		viz.SetTheme(Theme{})
	})
}