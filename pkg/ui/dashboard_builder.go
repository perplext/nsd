package ui

import (
	"fmt"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/perplext/nsd/pkg/netcap"
)

// DashboardBuilder provides an interface for building custom dashboards
type DashboardBuilder struct {
	app            *tview.Application
	pages          *tview.Pages
	monitor        *netcap.NetworkMonitor
	registry       *VisualizationRegistry
	theme          Theme
	
	// Current dashboard
	dashboard      *Dashboard
	selectedViz    Visualization
	
	// Builder UI components
	mainFlex       *tview.Flex
	vizList        *tview.List
	previewArea    *tview.TextView
	gridConfig     *tview.Form
	
	// Grid configuration
	gridRows       int
	gridCols       int
	
	// Callbacks
	onSave         func(layout DashboardLayout)
	onCancel       func()
}

// NewDashboardBuilder creates a new dashboard builder
func NewDashboardBuilder(app *tview.Application, monitor *netcap.NetworkMonitor, registry *VisualizationRegistry) *DashboardBuilder {
	db := &DashboardBuilder{
		app:      app,
		monitor:  monitor,
		registry: registry,
		gridRows: 3,
		gridCols: 3,
		pages:    tview.NewPages(),
	}
	
	db.dashboard = NewDashboard(registry, monitor)
	db.setupUI()
	
	return db
}

// SetTheme sets the theme
func (db *DashboardBuilder) SetTheme(theme Theme) {
	db.theme = theme
	db.dashboard.SetTheme(theme)
}

// setupUI creates the builder interface
func (db *DashboardBuilder) setupUI() {
	// Visualization list
	db.vizList = tview.NewList()
	db.vizList.SetBorder(true).SetTitle("Available Visualizations")
	
	// Add all visualizations to list
	vizs := db.registry.GetAll()
	for _, viz := range vizs {
		v := viz // Capture for closure
		db.vizList.AddItem(v.GetName(), v.GetDescription(), 0, func() {
			db.selectVisualization(v)
		})
	}
	
	// Preview area
	db.previewArea = tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(false)
	db.previewArea.SetBorder(true).SetTitle("Preview")
	
	// Grid configuration form
	db.gridConfig = tview.NewForm()
	db.gridConfig.SetBorder(true).SetTitle("Grid Configuration")
	
	db.gridConfig.
		AddInputField("Rows", fmt.Sprintf("%d", db.gridRows), 5, nil, func(text string) {
			if rows := parseIntOrDefault(text, 3); rows > 0 && rows <= 10 {
				db.gridRows = rows
			}
		}).
		AddInputField("Columns", fmt.Sprintf("%d", db.gridCols), 5, nil, func(text string) {
			if cols := parseIntOrDefault(text, 3); cols > 0 && cols <= 10 {
				db.gridCols = cols
			}
		}).
		AddButton("Apply Grid", func() {
			db.applyGridConfiguration()
		})
	
	// Dashboard view
	dashboardView := db.dashboard
	dashboardView.SetBorder(true).SetTitle("Dashboard Preview")
	
	// Control buttons
	controlForm := tview.NewForm()
	controlForm.SetBorder(true).SetTitle("Controls")
	
	controlForm.
		AddButton("Add to Dashboard", func() {
			db.addSelectedVisualization()
		}).
		AddButton("Clear Dashboard", func() {
			db.clearDashboard()
		}).
		AddButton("Save Dashboard", func() {
			db.saveDashboard()
		}).
		AddButton("Cancel", func() {
			if db.onCancel != nil {
				db.onCancel()
			}
		})
	
	// Layout
	leftPanel := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(db.vizList, 0, 2, true).
		AddItem(db.gridConfig, 8, 0, false).
		AddItem(controlForm, 8, 0, false)
	
	rightPanel := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(dashboardView, 0, 3, false).
		AddItem(db.previewArea, 0, 1, false)
	
	db.mainFlex = tview.NewFlex().
		AddItem(leftPanel, 0, 1, true).
		AddItem(rightPanel, 0, 2, false)
	
	// Keyboard shortcuts
	db.mainFlex.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEscape:
			if db.onCancel != nil {
				db.onCancel()
			}
			return nil
		case tcell.KeyTab:
			// Cycle focus
			return event
		}
		
		switch event.Rune() {
		case 'a', 'A':
			db.addSelectedVisualization()
			return nil
		case 'c', 'C':
			db.clearDashboard()
			return nil
		case 's', 'S':
			db.saveDashboard()
			return nil
		}
		
		return event
	})
	
	// Initial grid setup
	db.applyGridConfiguration()
}

// GetView returns the main view
func (db *DashboardBuilder) GetView() tview.Primitive {
	return db.mainFlex
}

// selectVisualization selects a visualization for preview
func (db *DashboardBuilder) selectVisualization(viz Visualization) {
	db.selectedViz = viz
	
	// Update preview
	preview := fmt.Sprintf("[yellow]%s[white]\n\n", viz.GetName())
	preview += fmt.Sprintf("Description: %s\n\n", viz.GetDescription())
	
	minW, minH := viz.GetMinSize()
	preview += fmt.Sprintf("Minimum Size: %dx%d\n", minW, minH)
	preview += fmt.Sprintf("Supports Fullscreen: %v\n\n", viz.SupportsFullscreen())
	
	preview += "[green]Press 'A' to add to dashboard[white]\n"
	
	db.previewArea.SetText(preview)
}

// addSelectedVisualization adds the selected visualization to the dashboard
func (db *DashboardBuilder) addSelectedVisualization() {
	if db.selectedViz == nil {
		return
	}
	
	// Find next available position
	for row := 0; row < db.gridRows; row++ {
		for col := 0; col < db.gridCols; col++ {
			if db.isPositionAvailable(row, col) {
				// Add visualization at this position
				vizConfig := DashboardVisualization{
					ID:      db.selectedViz.GetID(),
					Row:     row,
					Col:     col,
					RowSpan: 1,
					ColSpan: 1,
				}
				
				// Update layout
				layout := db.dashboard.layout
				layout.Visualizations = append(layout.Visualizations, vizConfig)
				layout.GridRows = db.gridRows
				layout.GridCols = db.gridCols
				
				db.dashboard.SetLayout(layout)
				db.updateDashboard()
				return
			}
		}
	}
	
	// No space available
	db.showMessage("No space available in dashboard")
}

// isPositionAvailable checks if a grid position is available
func (db *DashboardBuilder) isPositionAvailable(row, col int) bool {
	for _, viz := range db.dashboard.layout.Visualizations {
		if viz.Row == row && viz.Col == col {
			return false
		}
	}
	return true
}

// clearDashboard clears all visualizations
func (db *DashboardBuilder) clearDashboard() {
	layout := DashboardLayout{
		GridRows: db.gridRows,
		GridCols: db.gridCols,
		Visualizations: []DashboardVisualization{},
	}
	db.dashboard.SetLayout(layout)
	db.updateDashboard()
}

// applyGridConfiguration applies the grid configuration
func (db *DashboardBuilder) applyGridConfiguration() {
	layout := db.dashboard.layout
	layout.GridRows = db.gridRows
	layout.GridCols = db.gridCols
	
	// Remove visualizations that are now out of bounds
	newVizs := []DashboardVisualization{}
	for _, viz := range layout.Visualizations {
		if viz.Row < db.gridRows && viz.Col < db.gridCols {
			newVizs = append(newVizs, viz)
		}
	}
	layout.Visualizations = newVizs
	
	db.dashboard.SetLayout(layout)
	db.updateDashboard()
}

// updateDashboard updates the dashboard display
func (db *DashboardBuilder) updateDashboard() {
	// Trigger update
	go func() {
		db.dashboard.Update()
		db.app.Draw()
	}()
}

// saveDashboard saves the current dashboard layout
func (db *DashboardBuilder) saveDashboard() {
	if db.onSave != nil {
		layout := db.dashboard.layout
		layout.Name = "Custom Dashboard"
		layout.Description = fmt.Sprintf("%dx%d grid with %d visualizations",
			db.gridRows, db.gridCols, len(layout.Visualizations))
		
		db.onSave(layout)
	}
}

// showMessage shows a temporary message
func (db *DashboardBuilder) showMessage(msg string) {
	modal := tview.NewModal().
		SetText(msg).
		AddButtons([]string{"OK"}).
		SetDoneFunc(func(_ int, _ string) {
			db.app.SetRoot(db.mainFlex, true)
		})
	
	db.app.SetRoot(modal, true)
}

// SetOnSave sets the save callback
func (db *DashboardBuilder) SetOnSave(fn func(DashboardLayout)) {
	db.onSave = fn
}

// SetOnCancel sets the cancel callback
func (db *DashboardBuilder) SetOnCancel(fn func()) {
	db.onCancel = fn
}

// parseIntOrDefault parses an integer or returns default
func parseIntOrDefault(s string, def int) int {
	var val int
	if _, err := fmt.Sscanf(s, "%d", &val); err == nil {
		return val
	}
	return def
}

// DashboardManager manages saved dashboards
type DashboardManager struct {
	dashboards map[string]DashboardLayout
}

// NewDashboardManager creates a new dashboard manager
func NewDashboardManager() *DashboardManager {
	dm := &DashboardManager{
		dashboards: make(map[string]DashboardLayout),
	}
	
	// Add some default dashboards
	dm.addDefaultDashboards()
	
	return dm
}

// addDefaultDashboards adds pre-configured dashboards
func (dm *DashboardManager) addDefaultDashboards() {
	// Network Overview Dashboard
	dm.dashboards["overview"] = DashboardLayout{
		Name:        "Network Overview",
		Description: "Comprehensive network monitoring dashboard",
		GridRows:    3,
		GridCols:    3,
		Visualizations: []DashboardVisualization{
			{ID: "speedometer", Row: 0, Col: 0, RowSpan: 1, ColSpan: 1},
			{ID: "heartbeat", Row: 0, Col: 1, RowSpan: 1, ColSpan: 2},
			{ID: "sankey", Row: 1, Col: 0, RowSpan: 1, ColSpan: 2},
			{ID: "weather", Row: 1, Col: 2, RowSpan: 1, ColSpan: 1},
			{ID: "packet_dist", Row: 2, Col: 0, RowSpan: 1, ColSpan: 1},
			{ID: "conn_lifetime", Row: 2, Col: 1, RowSpan: 1, ColSpan: 2},
		},
	}
	
	// Security Dashboard
	dm.dashboards["security"] = DashboardLayout{
		Name:        "Security Monitor",
		Description: "Focus on security-relevant network activity",
		GridRows:    2,
		GridCols:    3,
		Visualizations: []DashboardVisualization{
			{ID: "constellation", Row: 0, Col: 0, RowSpan: 1, ColSpan: 2},
			{ID: "dns_timeline", Row: 0, Col: 2, RowSpan: 1, ColSpan: 1},
			{ID: "sunburst", Row: 1, Col: 0, RowSpan: 1, ColSpan: 1},
			{ID: "matrix", Row: 1, Col: 1, RowSpan: 1, ColSpan: 2},
		},
	}
	
	// Performance Dashboard
	dm.dashboards["performance"] = DashboardLayout{
		Name:        "Performance Monitor",
		Description: "Network performance and bandwidth analysis",
		GridRows:    2,
		GridCols:    2,
		Visualizations: []DashboardVisualization{
			{ID: "speedometer", Row: 0, Col: 0, RowSpan: 1, ColSpan: 1},
			{ID: "heartbeat", Row: 0, Col: 1, RowSpan: 1, ColSpan: 1},
			{ID: "heatmap", Row: 1, Col: 0, RowSpan: 1, ColSpan: 1},
			{ID: "radial", Row: 1, Col: 1, RowSpan: 1, ColSpan: 1},
		},
	}
	
	// Protocol Analysis Dashboard
	dm.dashboards["protocols"] = DashboardLayout{
		Name:        "Protocol Analysis",
		Description: "Comprehensive FTP, SSH, POP3, and IMAP protocol monitoring",
		GridRows:    1,
		GridCols:    1,
		Visualizations: []DashboardVisualization{
			{ID: "protocol_dashboard", Row: 0, Col: 0, RowSpan: 1, ColSpan: 1},
		},
	}
}

// GetDashboard returns a dashboard by name
func (dm *DashboardManager) GetDashboard(name string) (DashboardLayout, bool) {
	layout, exists := dm.dashboards[name]
	return layout, exists
}

// SaveDashboard saves a dashboard
func (dm *DashboardManager) SaveDashboard(name string, layout DashboardLayout) {
	dm.dashboards[name] = layout
}

// ListDashboards returns all dashboard names
func (dm *DashboardManager) ListDashboards() []string {
	names := make([]string, 0, len(dm.dashboards))
	for name := range dm.dashboards {
		names = append(names, name)
	}
	return names
}