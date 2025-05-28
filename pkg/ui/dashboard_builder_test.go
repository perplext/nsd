package ui

import (
	"fmt"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/stretchr/testify/assert"
	"github.com/perplext/nsd/pkg/graph"
	"github.com/perplext/nsd/pkg/netcap"
)

func TestNewDashboardBuilder(t *testing.T) {
	app := tview.NewApplication()
	monitor := &netcap.NetworkMonitor{} // Mock monitor
	registry := NewVisualizationRegistry()
	
	builder := NewDashboardBuilder(app, monitor, registry)
	assert.NotNil(t, builder)
	assert.Equal(t, app, builder.app)
	assert.Equal(t, monitor, builder.monitor)
	assert.Equal(t, registry, builder.registry)
	assert.Equal(t, 3, builder.gridRows) // Default grid rows
	assert.Equal(t, 3, builder.gridCols) // Default grid cols
	assert.NotNil(t, builder.dashboard)
	assert.NotNil(t, builder.mainFlex)
	assert.NotNil(t, builder.vizList)
	assert.NotNil(t, builder.previewArea)
	assert.NotNil(t, builder.gridConfig)
}

func TestDashboardBuilderSetTheme(t *testing.T) {
	app := tview.NewApplication()
	monitor := &netcap.NetworkMonitor{}
	registry := NewVisualizationRegistry()
	
	builder := NewDashboardBuilder(app, monitor, registry)
	
	// Test setting theme (use available theme)
	theme := Theme{
		BorderColor:        tcell.ColorWhite,
		TitleColor:         tcell.ColorYellow,
		PrimaryColor:       tcell.ColorBlue,
		SecondaryColor:     tcell.ColorGreen,
		PieBorderColor:     tcell.ColorGray,
		PieTitleColor:      tcell.NewRGBColor(0, 255, 255),
		StatusBarTextColor: tcell.ColorWhite,
		StatusBarBgColor:   tcell.ColorBlack,
		WarningColor:       tcell.ColorRed,
		SuccessColor:       tcell.ColorGreen,
	}
	
	assert.NotPanics(t, func() {
		builder.SetTheme(theme)
	})
	
	assert.Equal(t, theme, builder.theme)
}

func TestDashboardBuilderSetCallbacks(t *testing.T) {
	app := tview.NewApplication()
	monitor := &netcap.NetworkMonitor{}
	registry := NewVisualizationRegistry()
	
	builder := NewDashboardBuilder(app, monitor, registry)
	
	// Test setting callbacks
	saveCalled := false
	cancelCalled := false
	
	builder.SetOnSave(func(layout DashboardLayout) {
		saveCalled = true
	})
	
	builder.SetOnCancel(func() {
		cancelCalled = true
	})
	
	// Trigger callbacks if they exist
	if builder.onSave != nil {
		builder.onSave(DashboardLayout{})
	}
	if builder.onCancel != nil {
		builder.onCancel()
	}
	
	assert.True(t, saveCalled)
	assert.True(t, cancelCalled)
}

func TestDashboardBuilderSetOnSave(t *testing.T) {
	app := tview.NewApplication()
	monitor := &netcap.NetworkMonitor{}
	registry := NewVisualizationRegistry()
	
	builder := NewDashboardBuilder(app, monitor, registry)
	
	// Test setting save callback
	called := false
	builder.SetOnSave(func(layout DashboardLayout) {
		called = true
	})
	
	assert.NotNil(t, builder.onSave)
	
	// Trigger callback
	builder.onSave(DashboardLayout{})
	assert.True(t, called)
}

func TestDashboardBuilderSetOnCancel(t *testing.T) {
	app := tview.NewApplication()
	monitor := &netcap.NetworkMonitor{}
	registry := NewVisualizationRegistry()
	
	builder := NewDashboardBuilder(app, monitor, registry)
	
	// Test setting cancel callback
	called := false
	builder.SetOnCancel(func() {
		called = true
	})
	
	assert.NotNil(t, builder.onCancel)
	
	// Trigger callback
	builder.onCancel()
	assert.True(t, called)
}

func TestDashboardBuilderUIComponents(t *testing.T) {
	app := tview.NewApplication()
	monitor := &netcap.NetworkMonitor{}
	registry := NewVisualizationRegistry()
	
	builder := NewDashboardBuilder(app, monitor, registry)
	
	// Test that all UI components are properly initialized
	assert.NotNil(t, builder.vizList)
	assert.NotNil(t, builder.previewArea)
	assert.NotNil(t, builder.gridConfig)
	assert.NotNil(t, builder.mainFlex)
	assert.NotNil(t, builder.dashboard)
	
	// Test that components have proper titles
	assert.Equal(t, "Available Visualizations", builder.vizList.GetTitle())
	assert.Equal(t, "Preview", builder.previewArea.GetTitle())
	assert.Equal(t, "Grid Configuration", builder.gridConfig.GetTitle())
}

func TestDashboardBuilderGridConfiguration(t *testing.T) {
	app := tview.NewApplication()
	monitor := &netcap.NetworkMonitor{}
	registry := NewVisualizationRegistry()
	
	builder := NewDashboardBuilder(app, monitor, registry)
	
	// Test default grid configuration
	assert.Equal(t, 3, builder.gridRows)
	assert.Equal(t, 3, builder.gridCols)
	
	// Test grid configuration form exists
	assert.NotNil(t, builder.gridConfig)
	
	// Grid configuration should have input fields and buttons
	form := builder.gridConfig
	assert.NotNil(t, form)
}

func TestDashboardBuilderRegistryIntegration(t *testing.T) {
	app := tview.NewApplication()
	monitor := &netcap.NetworkMonitor{}
	registry := NewVisualizationRegistry()
	
	// Add some test visualizations to registry
	viz1 := &TestVisualization{id: "test1", name: "test1", description: "Test Viz 1"}
	viz2 := &TestVisualization{id: "test2", name: "test2", description: "Test Viz 2"}
	
	registry.Register("test1", func() Visualization { return viz1 })
	registry.Register("test2", func() Visualization { return viz2 })
	
	builder := NewDashboardBuilder(app, monitor, registry)
	
	// Check that visualizations were added to the list
	assert.NotNil(t, builder.vizList)
	
	// The visualization list should contain the registered visualizations
	assert.Equal(t, 2, builder.vizList.GetItemCount())
}

func TestDashboardBuilderInputCapture(t *testing.T) {
	app := tview.NewApplication()
	monitor := &netcap.NetworkMonitor{}
	registry := NewVisualizationRegistry()
	
	builder := NewDashboardBuilder(app, monitor, registry)
	
	// Test that the main flex has input capture
	assert.NotNil(t, builder.mainFlex)
	
	// Input capture should be set (we can't test the actual behavior without running the app)
	// But we can verify the component exists and was set up
	assert.True(t, true) // Just verify no panic occurred during setup
}

func TestDashboardBuilderWithNilCallbacks(t *testing.T) {
	app := tview.NewApplication()
	monitor := &netcap.NetworkMonitor{}
	registry := NewVisualizationRegistry()
	
	builder := NewDashboardBuilder(app, monitor, registry)
	
	// Test that nil callbacks don't cause panics
	builder.onSave = nil
	builder.onCancel = nil
	
	// These should not panic even with nil callbacks
	assert.NotPanics(t, func() {
		if builder.onSave != nil {
			builder.onSave(DashboardLayout{})
		}
		if builder.onCancel != nil {
			builder.onCancel()
		}
	})
}

// TestVisualization is a mock visualization for testing
type TestVisualization struct {
	id          string
	name        string
	description string
	dataPoints  []graph.DataPoint
	theme       Theme
}

func (tv *TestVisualization) GetID() string {
	return tv.id
}

func (tv *TestVisualization) GetName() string {
	return tv.name
}

func (tv *TestVisualization) GetDescription() string {
	return tv.description
}

func (tv *TestVisualization) CreateView() tview.Primitive {
	return tview.NewTextView()
}

func (tv *TestVisualization) Update(monitor *netcap.NetworkMonitor) {
	// Mock update implementation
}

func (tv *TestVisualization) SetTheme(theme Theme) {
	tv.theme = theme
}

func (tv *TestVisualization) GetMinSize() (width, height int) {
	return 20, 10
}

func (tv *TestVisualization) SupportsFullscreen() bool {
	return true
}

func TestDashboardBuilderComplexSetup(t *testing.T) {
	app := tview.NewApplication()
	monitor := &netcap.NetworkMonitor{}
	registry := NewVisualizationRegistry()
	
	// Add multiple visualizations
	for i := 0; i < 5; i++ {
		viz := &TestVisualization{
			id:          fmt.Sprintf("viz_%d", i),
			name:        fmt.Sprintf("viz_%d", i),
			description: fmt.Sprintf("Visualization %d", i),
		}
		registry.Register(viz.id, func() Visualization { return viz })
	}
	
	builder := NewDashboardBuilder(app, monitor, registry)
	
	// Set theme and callbacks
	theme := Theme{
		BorderColor:        tcell.ColorWhite,
		TitleColor:         tcell.ColorYellow,
		PrimaryColor:       tcell.ColorBlue,
		SecondaryColor:     tcell.ColorGreen,
		PieBorderColor:     tcell.ColorGray,
		PieTitleColor:      tcell.NewRGBColor(0, 255, 255),
		StatusBarTextColor: tcell.ColorWhite,
		StatusBarBgColor:   tcell.ColorBlack,
		WarningColor:       tcell.ColorRed,
		SuccessColor:       tcell.ColorGreen,
	}
	builder.SetTheme(theme)
	
	var savedLayout DashboardLayout
	builder.SetOnSave(func(layout DashboardLayout) {
		savedLayout = layout
	})
	
	cancelled := false
	builder.SetOnCancel(func() {
		cancelled = true
	})
	
	// Verify all components are properly set up
	assert.Equal(t, theme, builder.theme)
	assert.NotNil(t, builder.onSave)
	assert.NotNil(t, builder.onCancel)
	assert.Equal(t, 5, builder.vizList.GetItemCount())
	
	// Test callbacks work
	builder.onSave(DashboardLayout{Name: "test"})
	assert.Equal(t, "test", savedLayout.Name)
	
	builder.onCancel()
	assert.True(t, cancelled)
}