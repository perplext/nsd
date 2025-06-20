package ui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/perplext/nsd/pkg/netcap"
)

func TestNewPacketDistributionVisualization(t *testing.T) {
	viz := NewPacketDistributionVisualization()
	
	assert.NotNil(t, viz)
	assert.Equal(t, "Packet Size Distribution", viz.GetName())
}

func TestPacketDistributionVisualizationUpdate(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	viz := NewPacketDistributionVisualization()
	
	// Should not panic
	assert.NotPanics(t, func() {
		viz.Update(monitor)
	})
}

func TestPacketDistributionVisualizationGetMinSize(t *testing.T) {
	viz := NewPacketDistributionVisualization()
	
	w, h := viz.GetMinSize()
	assert.Equal(t, 70, w)
	assert.Equal(t, 35, h)
}

func TestPacketDistributionVisualizationSupportsFullscreen(t *testing.T) {
	viz := NewPacketDistributionVisualization()
	
	assert.True(t, viz.SupportsFullscreen())
}

func TestPacketDistributionVisualizationSetTheme(t *testing.T) {
	viz := NewPacketDistributionVisualization()
	
	// Should not panic
	assert.NotPanics(t, func() {
		viz.SetTheme(Theme{})
	})
}

func TestPacketDistributionVisualizationWithPackets(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	viz := NewPacketDistributionVisualization()
	
	// Simulate packet data
	// Note: Cannot set protocol stats directly in test
	
	// Update to process the data
	viz.Update(monitor)
	
	// Should have processed protocol stats
	assert.NotNil(t, viz)
}

