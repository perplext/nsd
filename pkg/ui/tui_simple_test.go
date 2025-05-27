package ui

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/user/nsd/pkg/netcap"
)

// Test NewUI
func TestNewUI_Creation(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	ui := NewUI(monitor)
	
	require.NotNil(t, ui)
	assert.NotNil(t, ui.app)
	assert.NotNil(t, ui.networkMonitor)
	assert.NotNil(t, ui.pages)
	assert.NotNil(t, ui.statsView)
	assert.NotNil(t, ui.connectionTable)
	assert.NotNil(t, ui.interfaceList)
	assert.NotNil(t, ui.protocolView)
	assert.NotNil(t, ui.statusBar)
	assert.Equal(t, time.Second, ui.updateInterval)
}

// Test SetTheme
func TestUI_SetTheme(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	ui := NewUI(monitor)
	
	// Test with valid theme names
	themes := []string{"dark", "light", "matrix", "solarized", "dracula", "monokai"}
	for _, theme := range themes {
		result := ui.SetTheme(theme)
		assert.Equal(t, ui, result) // Check method chaining
	}
	
	// Test with invalid theme
	ui.SetTheme("non-existent-theme")
	// Should handle gracefully
}

// Test SetStyle
func TestUI_SetStyle(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	ui := NewUI(monitor)
	
	// Test different styles
	styles := []string{"braille", "block", "tty"}
	for _, style := range styles {
		result := ui.SetStyle(style)
		assert.Equal(t, ui, result) // Check method chaining
	}
}

// Test SetGradientEnabled
func TestUI_SetGradientEnabled(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	ui := NewUI(monitor)
	
	// Enable gradient
	result := ui.SetGradientEnabled(true)
	assert.Equal(t, ui, result)
	
	// Disable gradient
	result = ui.SetGradientEnabled(false)
	assert.Equal(t, ui, result)
}

// Test Stop method
func TestUI_Stop(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	ui := NewUI(monitor)
	
	// Stop should not panic even without timer
	assert.NotPanics(t, func() {
		ui.Stop()
	})
}