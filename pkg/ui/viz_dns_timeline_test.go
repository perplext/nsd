package ui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/perplext/nsd/pkg/netcap"
)

func TestNewDNSTimelineVisualization(t *testing.T) {
	viz := NewDNSTimelineVisualization()
	
	assert.NotNil(t, viz)
	assert.Equal(t, "DNS Query Timeline", viz.GetName())
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
	assert.Equal(t, 80, w)
	assert.Equal(t, 20, h)
}

func TestDNSTimelineVisualizationSupportsFullscreen(t *testing.T) {
	viz := NewDNSTimelineVisualization()
	
	assert.False(t, viz.SupportsFullscreen())
}

func TestDNSTimelineVisualizationSetTheme(t *testing.T) {
	viz := NewDNSTimelineVisualization()
	
	// Should not panic
	assert.NotPanics(t, func() {
		viz.SetTheme(Theme{})
	})
}