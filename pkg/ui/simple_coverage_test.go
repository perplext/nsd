package ui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/stretchr/testify/assert"
	"github.com/user/nsd/pkg/netcap"
)

// Test theme functions that need coverage
func TestThemeCoverage(t *testing.T) {
	// Test GetUsageColor
	colors := []float64{0.0, 0.3, 0.5, 0.7, 0.9, 1.2}
	for _, usage := range colors {
		color := GetUsageColor(usage)
		assert.NotEqual(t, tcell.ColorDefault, color)
	}
	
	// Test DetectAutoTheme
	theme := DetectAutoTheme()
	assert.NotEmpty(t, theme)
	
	// Test interpolateColor
	result := interpolateColor(tcell.ColorRed, tcell.ColorGreen, 0.5)
	assert.NotEqual(t, tcell.ColorDefault, result)
	
	// Test colorToHex
	assert.Equal(t, "#ff0000", colorToHex(tcell.ColorRed))
	assert.Equal(t, "#00ff00", colorToHex(tcell.ColorGreen))
	assert.Equal(t, "#0000ff", colorToHex(tcell.ColorBlue))
	
	// Test parseHex
	assert.NotEqual(t, tcell.ColorDefault, parseHex("#ff0000"))
	assert.Equal(t, tcell.ColorDefault, parseHex("invalid"))
	assert.Equal(t, tcell.ColorDefault, parseHex("#gg0000"))
	assert.Equal(t, tcell.ColorDefault, parseHex("#f"))
}

// Test LoadThemes
func TestLoadThemesCoverage(t *testing.T) {
	// Test with non-existent file
	err := LoadThemes("/non/existent/path/theme.json")
	assert.Error(t, err)
	
	// Test with valid directory but no theme files
	tmpDir, err := os.MkdirTemp("", "themes_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	
	// Test with invalid extension
	err = LoadThemes(filepath.Join(tmpDir, "theme.txt"))
	assert.Error(t, err)
}

// Test ExportTheme
func TestExportThemeCoverage(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "export_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	
	// Test export to JSON
	jsonPath := filepath.Join(tmpDir, "theme.json")
	err = ExportTheme("test", jsonPath)
	assert.NoError(t, err)
	
	// Test export to YAML
	yamlPath := filepath.Join(tmpDir, "theme.yaml") 
	err = ExportTheme("test", yamlPath)
	assert.NoError(t, err)
	
	// Test export to invalid path
	err = ExportTheme("test", "/invalid/path/theme.json")
	assert.Error(t, err)
}

// Test BorderStyleNames
func TestBorderStyleNamesCoverage(t *testing.T) {
	names := BorderStyleNames()
	assert.NotEmpty(t, names)
	assert.GreaterOrEqual(t, len(names), 8) // We have at least 8 styles
}

// Test animation helpers
func TestAnimationCoverage(t *testing.T) {
	// Test sin function
	assert.Equal(t, float64(0), sin(0))
	assert.InDelta(t, 1.0, sin(90), 0.01)
	
	// Test GetAnimatedBorderChar with different positions
	styles := GetBorderStyle("rounded")
	positions := []string{"top", "bottom", "left", "right", "topLeft", "topRight", "bottomLeft", "bottomRight"}
	
	for _, pos := range positions {
		char := GetAnimatedBorderChar(styles, pos, 0)
		assert.NotEqual(t, rune(0), char)
	}
}

// Test parseIntOrDefault
func TestParseIntOrDefaultCoverage(t *testing.T) {
	assert.Equal(t, 42, parseIntOrDefault("42", 10))
	assert.Equal(t, 10, parseIntOrDefault("abc", 10))
	assert.Equal(t, 10, parseIntOrDefault("", 10))
}

// Test visualization functions
func TestVisualizationCoverage(t *testing.T) {
	// Create registry
	registry := NewVisualizationRegistry()
	assert.NotNil(t, registry)
	
	// Register and get visualization
	registry.Register("test", NewMatrixRainVisualization)
	viz := registry.Get("test")
	assert.NotNil(t, viz)
	
	// Get non-existent
	assert.Nil(t, registry.Get("nonexistent"))
	
	// List
	list := registry.List()
	assert.Contains(t, list, "test")
	
	// GetAll
	all := registry.GetAll()
	assert.NotEmpty(t, all)
	
	// Test BaseVisualization
	base := &BaseVisualization{}
	w, h := base.GetMinSize()
	assert.GreaterOrEqual(t, w, 0)
	assert.GreaterOrEqual(t, h, 0)
	assert.False(t, base.SupportsFullscreen())
	
	// SetTheme should not panic
	base.SetTheme(Theme{BorderColor: tcell.ColorWhite})
}

// Test Dashboard
func TestDashboardCoverage(t *testing.T) {
	monitor := netcap.NewNetworkMonitor()
	registry := NewVisualizationRegistry()
	
	dashboard := NewDashboard(registry, monitor)
	assert.NotNil(t, dashboard)
	
	// Test Update
	dashboard.Update()
	
	// Test SetTheme
	dashboard.SetTheme(Theme{BorderColor: tcell.ColorWhite})
	
	// Test SetLayout with empty layout
	layout := DashboardLayout{}
	assert.NotPanics(t, func() {
		dashboard.SetLayout(layout)
	})
}

// Test DashboardBuilder
func TestDashboardBuilderCoverage(t *testing.T) {
	app := tview.NewApplication()
	monitor := netcap.NewNetworkMonitor()
	registry := NewVisualizationRegistry()
	
	builder := NewDashboardBuilder(app, monitor, registry)
	assert.NotNil(t, builder)
	
	// Test SetTheme
	builder.SetTheme(Theme{BorderColor: tcell.ColorWhite})
	
	// Test updateDashboard
	builder.updateDashboard()
	
	// Test SetOnSave and SetOnCancel
	builder.SetOnSave(func(DashboardLayout) {})
	builder.SetOnCancel(func() {})
	
	// Test applyGridConfiguration
	builder.applyGridConfiguration()
}

// Test StyledGrid coverage
func TestStyledGridCoverage(t *testing.T) {
	grid := NewStyledGrid()
	assert.NotNil(t, grid)
	
	// Test all setters
	grid.SetBorders(true)
	grid.SetBorderStyle("rounded")
	grid.SetBorderColor(tcell.ColorWhite)
	grid.SetAnimation("Rainbow")
	grid.SetAnimationFrame(10)
	grid.SetColumns(1, 2, 3)
	grid.SetRows(1, 2, 3)
	grid.SetGap(1)
	
	// Test AddItem
	item := tview.NewBox()
	grid.AddItem(item, 0, 0, 1, 1, 0, 0, false)
	
	// Test Clear
	grid.Clear()
	
	// Test Focus
	grid.Focus(func(p tview.Primitive) {})
	assert.True(t, grid.HasFocus())
	
	// Test InputHandler
	handler := grid.InputHandler()
	assert.NotNil(t, handler)
}

// Test CustomBox coverage
func TestCustomBoxCoverage(t *testing.T) {
	box := NewCustomBox(tview.NewBox())
	assert.NotNil(t, box)
	
	// Test setters
	box.SetTitle("Test")
	box.SetBorder(true)
	box.SetBorderStyle(GetBorderStyle("rounded"))
	
	// Test Focus
	box.Focus(func(p tview.Primitive) {})
	assert.True(t, box.HasFocus())
	
	// Test InputHandler
	handler := box.InputHandler()
	assert.NotNil(t, handler)
}

// Test WorldMap coverage
func TestWorldMapCoverage(t *testing.T) {
	wm := NewWorldMap()
	assert.NotNil(t, wm)
	
	// Mark countries
	wm.MarkCountry("US", '*')
	wm.MarkCountry("CN", '*')
	wm.MarkCountry("GB", '*')
	
	// Test Render
	output := wm.Render()
	assert.NotEmpty(t, output)
	
	// Test RenderWithColors
	colors := map[string]int{"US": 1, "CN": 2}
	colored := wm.RenderWithColors(colors, 5)
	assert.NotEmpty(t, colored)
	
	// Test getting map size
	assert.Equal(t, 84, wm.width)
	assert.Equal(t, 28, wm.height)
	
	// Test Clear
	wm.Clear()
}