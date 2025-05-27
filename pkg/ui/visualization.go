package ui

import (
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/user/nsd/pkg/netcap"
)

// Visualization represents a network data visualization
type Visualization interface {
	// GetID returns the unique identifier for this visualization
	GetID() string
	
	// GetName returns the display name
	GetName() string
	
	// GetDescription returns a brief description
	GetDescription() string
	
	// CreateView creates the tview primitive for this visualization
	CreateView() tview.Primitive
	
	// Update updates the visualization with new data
	Update(monitor *netcap.NetworkMonitor)
	
	// SetTheme sets the color theme
	SetTheme(theme Theme)
	
	// GetMinSize returns minimum width and height requirements
	GetMinSize() (width, height int)
	
	// SupportsFullscreen indicates if this viz works well fullscreen
	SupportsFullscreen() bool
}

// VisualizationRegistry manages available visualizations
type VisualizationRegistry struct {
	visualizations map[string]func() Visualization
}

// NewVisualizationRegistry creates a new registry
func NewVisualizationRegistry() *VisualizationRegistry {
	return &VisualizationRegistry{
		visualizations: make(map[string]func() Visualization),
	}
}

// Register adds a visualization to the registry
func (r *VisualizationRegistry) Register(id string, factory func() Visualization) {
	r.visualizations[id] = factory
}

// Get creates a new instance of a visualization
func (r *VisualizationRegistry) Get(id string) Visualization {
	if factory, exists := r.visualizations[id]; exists {
		return factory()
	}
	return nil
}

// List returns all available visualization IDs
func (r *VisualizationRegistry) List() []string {
	ids := make([]string, 0, len(r.visualizations))
	for id := range r.visualizations {
		ids = append(ids, id)
	}
	return ids
}

// GetAll returns all available visualizations
func (r *VisualizationRegistry) GetAll() []Visualization {
	vizs := make([]Visualization, 0, len(r.visualizations))
	for _, factory := range r.visualizations {
		vizs = append(vizs, factory())
	}
	return vizs
}

// BaseVisualization provides common functionality for visualizations
type BaseVisualization struct {
	view      tview.Primitive
	theme     Theme
	monitor   *netcap.NetworkMonitor
	textView  *tview.TextView
	borderBox *tview.Box
}

// SetTheme sets the color theme
func (b *BaseVisualization) SetTheme(theme Theme) {
	b.theme = theme
	if b.textView != nil {
		b.textView.SetBorderColor(theme.BorderColor).
			SetTitleColor(theme.TitleColor).
			SetBackgroundColor(tcell.ColorDefault)
	}
}

// GetMinSize returns default minimum size
func (b *BaseVisualization) GetMinSize() (width, height int) {
	return 30, 10
}

// SupportsFullscreen returns default value
func (b *BaseVisualization) SupportsFullscreen() bool {
	return true
}

// DashboardLayout represents a saved dashboard configuration
type DashboardLayout struct {
	Name           string                      `json:"name"`
	Description    string                      `json:"description"`
	Visualizations []DashboardVisualization    `json:"visualizations"`
	GridRows       int                         `json:"grid_rows"`
	GridCols       int                         `json:"grid_cols"`
}

// DashboardVisualization represents a visualization in a dashboard
type DashboardVisualization struct {
	ID       string `json:"id"`
	Row      int    `json:"row"`
	Col      int    `json:"col"`
	RowSpan  int    `json:"row_span"`
	ColSpan  int    `json:"col_span"`
	Settings map[string]interface{} `json:"settings,omitempty"`
}

// Dashboard manages a collection of visualizations
type Dashboard struct {
	*tview.Grid
	visualizations map[string]Visualization
	layout         DashboardLayout
	registry       *VisualizationRegistry
	theme          Theme
	monitor        *netcap.NetworkMonitor
}

// NewDashboard creates a new dashboard
func NewDashboard(registry *VisualizationRegistry, monitor *netcap.NetworkMonitor) *Dashboard {
	return &Dashboard{
		Grid:           tview.NewGrid(),
		visualizations: make(map[string]Visualization),
		registry:       registry,
		monitor:        monitor,
	}
}

// SetLayout applies a dashboard layout
func (d *Dashboard) SetLayout(layout DashboardLayout) error {
	d.Clear()
	d.layout = layout
	
	// Set grid dimensions
	rows := make([]int, layout.GridRows)
	cols := make([]int, layout.GridCols)
	d.SetRows(rows...).SetColumns(cols...)
	
	// Add visualizations
	for _, vizConfig := range layout.Visualizations {
		viz := d.registry.Get(vizConfig.ID)
		if viz == nil {
			continue
		}
		
		viz.SetTheme(d.theme)
		view := viz.CreateView()
		
		d.AddItem(view, vizConfig.Row, vizConfig.Col, 
			vizConfig.RowSpan, vizConfig.ColSpan, 0, 0, false)
		
		d.visualizations[vizConfig.ID] = viz
	}
	
	return nil
}

// Update updates all visualizations in the dashboard
func (d *Dashboard) Update() {
	for _, viz := range d.visualizations {
		viz.Update(d.monitor)
	}
}

// SetTheme sets the theme for all visualizations
func (d *Dashboard) SetTheme(theme Theme) {
	d.theme = theme
	for _, viz := range d.visualizations {
		viz.SetTheme(theme)
	}
}

// Global visualization registry
var GlobalRegistry = NewVisualizationRegistry()

// Register all visualizations
func init() {
	// Register all visualization types
	GlobalRegistry.Register("sankey", func() Visualization { return NewSankeyVisualization() })
	GlobalRegistry.Register("radial", func() Visualization { return NewRadialConnectionVisualization() })
	GlobalRegistry.Register("heartbeat", func() Visualization { return NewHeartbeatVisualization() })
	GlobalRegistry.Register("heatmap", func() Visualization { return NewHeatmapVisualization() })
	GlobalRegistry.Register("matrix", func() Visualization { return NewMatrixRainVisualization() })
	GlobalRegistry.Register("speedometer", func() Visualization { return NewSpeedometerVisualization() })
	GlobalRegistry.Register("sunburst", func() Visualization { return NewSunburstVisualization() })
	GlobalRegistry.Register("weather", func() Visualization { return NewWeatherMapVisualization() })
	GlobalRegistry.Register("constellation", func() Visualization { return NewConstellationVisualization() })
	GlobalRegistry.Register("dns_timeline", func() Visualization { return NewDNSTimelineVisualization() })
	GlobalRegistry.Register("packet_dist", func() Visualization { return NewPacketDistributionVisualization() })
	GlobalRegistry.Register("conn_lifetime", func() Visualization { return NewConnectionLifetimeVisualization() })
	// GlobalRegistry.Register("security_dashboard", func() Visualization { return NewSecurityDashboardVisualization() })
	// GlobalRegistry.Register("protocol_dashboard", func() Visualization { return NewProtocolDashboardVisualization() })
}