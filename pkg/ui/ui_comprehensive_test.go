package ui

import (
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/stretchr/testify/assert"
	"github.com/perplext/nsd/pkg/netcap"
)

func TestUICreation(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	
	ui := NewUI(monitor)
	assert.NotNil(t, ui)
	assert.NotNil(t, ui.app)
	assert.NotNil(t, ui.trafficGraph)
	assert.NotNil(t, ui.connectionTable)
	assert.NotNil(t, ui.statusBar)
}

func TestUIConfiguration(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	
	ui := NewUI(monitor)
	assert.NotNil(t, ui)
	
	// Test theme setting
	ui.SetTheme("Light")
	
	// Test style setting
	ui.SetStyle("ASCII")
	
	// Test gradient setting
	ui.SetGradientEnabled(true)
}

func TestVisualizationRegistration(t *testing.T) {
	registry := NewVisualizationRegistry()
	
	// Test registration
	vizFunc := func() Visualization {
		return NewMatrixRainVisualization()
	}
	
	registry.Register("test_viz", vizFunc)
	
	// Test retrieval
	viz := registry.Get("test_viz")
	assert.NotNil(t, viz)
	assert.Equal(t, "Matrix Rain", viz.GetName())
	
	// Test list
	list := registry.List()
	assert.Contains(t, list, "test_viz")
	
	// Test GetAll
	all := registry.GetAll()
	assert.NotEmpty(t, all)
	// Check if any visualization has the expected name
	found := false
	for _, v := range all {
		if v.GetName() == "Matrix Rain" {
			found = true
			break
		}
	}
	assert.True(t, found, "Should contain a visualization with name 'Matrix Rain'")
	
	// Test Get for non-existent
	nonExistent := registry.Get("non_existent")
	assert.Nil(t, nonExistent)
}

func TestDashboardOperations(t *testing.T) {
	registry := NewVisualizationRegistry()
	monitor := netcap.NewNetworkMonitor()
	
	// Register some visualizations
	registry.Register("matrix", NewMatrixRainVisualization)
	registry.Register("heatmap", NewHeatmapVisualization)
	
	dashboard := NewDashboard(registry, monitor)
	assert.NotNil(t, dashboard)
	
	// Test SetLayout with empty layout
	layout := DashboardLayout{}
	dashboard.SetLayout(layout)
	
	// Test SetTheme
	theme := Theme{
		BorderColor:     tcell.ColorWhite,
		TitleColor:      tcell.ColorYellow,
		PrimaryColor:    tcell.ColorGreen,
		SecondaryColor:  tcell.ColorBlue,
	}
	dashboard.SetTheme(theme)
}

func TestVisualizationFactory(t *testing.T) {
	// Test that all visualizations can be created
	vizTypes := []struct {
		factory func() Visualization
		name    string
	}{
		{NewMatrixRainVisualization, "Matrix Rain"},
		{NewHeatmapVisualization, "Traffic Heatmap"},
		{NewSankeyVisualization, "Network Flow Sankey"},
		{NewRadialConnectionVisualization, "Radial Connection Graph"},
		{NewSpeedometerVisualization, "Bandwidth Speedometer"},
		{NewSunburstVisualization, "Connection Sunburst"},
		{NewWeatherMapVisualization, "Network Weather"},
		{NewConstellationVisualization, "Port Constellation"},
		{NewConnectionLifetimeVisualization, "Connection Lifetime"},
		{NewDNSTimelineVisualization, "DNS Timeline"},
		{NewPacketDistributionVisualization, "Packet Size Distribution"},
		{NewHeartbeatVisualization, "Network Heartbeat"},
	}
	
	for _, vt := range vizTypes {
		t.Run(vt.name, func(t *testing.T) {
			viz := vt.factory()
			assert.NotNil(t, viz)
			assert.Equal(t, vt.name, viz.GetName())
			
			// Test common methods
			w, h := viz.GetMinSize()
			assert.Greater(t, w, 0)
			assert.Greater(t, h, 0)
			
			// Test SetTheme doesn't panic
			assert.NotPanics(t, func() {
				viz.SetTheme(Theme{})
			})
		})
	}
}

func TestUIStop(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	
	ui := NewUI(monitor)
	assert.NotNil(t, ui)
	
	// Test Stop doesn't panic
	assert.NotPanics(t, func() {
		ui.Stop()
	})
}

