package ui

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/user/nsd/pkg/graph"
	"github.com/user/nsd/pkg/netcap"
	"github.com/user/nsd/pkg/ui/i18n"
	"github.com/user/nsd/pkg/utils"
)

// UI represents the terminal user interface
type UI struct {
	app              *tview.Application
	pages            *tview.Pages
	networkMonitor   *netcap.NetworkMonitor
	interfaceList    *tview.List
	statsView        *tview.TextView
	connectionTable  *tview.Table
	detailView       *tview.TextView
	statusBar        *tview.TextView
	trafficGraph     *graph.MultiGraph
	networkGraph     *graph.GraphWidget
	cpuMemGraph      *graph.GraphWidget
	protocolView     *tview.TextView
	selectedIface    string
	selectedConnection *netcap.Connection // currently selected connection
	updateInterval   time.Duration
	stopChan         chan struct{}
	connections      []*netcap.Connection
	sortBy           string
	sortAscending    bool
	filterString     string
	bpfString        string           // current BPF filter
	packetTable      *tview.Table     // raw packet buffer view
	histView         *tview.TextView  // packet size histogram view
	dnsHttpView      *tview.TextView  // HTTP/DNS summary view
	geoView          *tview.Table     // Geo mapping view
	geoCache         map[string]*GeoLocation // cache IP->location data
	geoMapView       *tview.TextView  // ASCII world map view
	helpView         *tview.TextView  // Help screen view
	rawView         *tview.TextView  // raw packet hex view
	rawDumpLines    []string         // stored lines for search
	// Traffic rate calculation
	lastBytesIn      uint64
	lastBytesOut     uint64
	lastUpdateTime   time.Time
	panels           []*panel
	servicePieView   *tview.TextView
	protocolPieView  *tview.TextView
	securePieView    *tview.TextView
	ifaceStatsView   *tview.Table
	theme            Theme
	styleName        string
	paused           bool
	currentLayout    int
	layoutPresets    []string
	graphStyle       graph.GraphStyle
	markedConnections map[string]bool // Track marked connections for bulk operations
	connectionHistory map[string][]float64 // Track bandwidth history for sparklines
	recording         bool
	recordingStart    time.Time
	sessionData       *SessionRecording
	plugins           []PluginInfo
	pluginView        *tview.TextView
	showPlugins       bool
	selectedPlugin    int
	uiMutex           sync.Mutex   // Protect UI operations
	borderStyle       string       // Current border style
	borderAnimation   string       // Border animation type
	animationTicker   *time.Ticker // Animation update ticker
	animationFrame    int          // Current animation frame
	mainGrid          *StyledGrid  // Reference to main grid for animation updates
	startupVizID      string       // Visualization to show on startup
	startupDashboard  string       // Dashboard to show on startup
	startupFullscreen bool         // Start in fullscreen mode
}

// panel represents a UI section that can be toggled and positioned in the grid
type panel struct {
	id        string
	primitive tview.Primitive
	visible   bool
	row, col, rowSpan, colSpan int
	borderStyle string // Custom border style for this panel
	borderAnimation string // Custom animation for this panel
}

// PluginInfo stores information about a loaded plugin
type PluginInfo struct {
	Name        string
	Description string
	Output      []string
	LastUpdate  time.Time
	Status      string
}

// GeoLocation stores detailed geographic information
type GeoLocation struct {
	CountryCode string    `json:"countryCode"`
	Country     string    `json:"country"`
	Region      string    `json:"regionName"`
	City        string    `json:"city"`
	Latitude    float64   `json:"lat"`
	Longitude   float64   `json:"lon"`
	ISP         string    `json:"isp"`
	Org         string    `json:"org"`
	AS          string    `json:"as"`
	LastUpdate  time.Time
}

// SessionRecording stores recorded network session data
type SessionRecording struct {
	StartTime     time.Time                    `json:"start_time"`
	EndTime       time.Time                    `json:"end_time"`
	Interface     string                       `json:"interface"`
	Snapshots     []NetworkSnapshot            `json:"snapshots"`
	Events        []SessionEvent               `json:"events"`
	PacketCount   int                          `json:"packet_count"`
	TotalBytes    uint64                       `json:"total_bytes"`
}

// NetworkSnapshot captures network state at a point in time
type NetworkSnapshot struct {
	Timestamp   time.Time                      `json:"timestamp"`
	Connections []*netcap.Connection           `json:"connections"`
	Stats       map[string]*netcap.InterfaceStats `json:"stats"`
	BandwidthIn  float64                       `json:"bandwidth_in"`
	BandwidthOut float64                       `json:"bandwidth_out"`
}

// SessionEvent records user interactions and system events
type SessionEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	Details   string    `json:"details"`
}

// UIProfile stores UI configuration for save/load
type UIProfile struct {
	Name            string                 `json:"name"`
	Theme           string                 `json:"theme"`
	BorderStyle     string                 `json:"border_style"`
	BorderAnimation string                 `json:"border_animation"`
	LayoutPreset    int                    `json:"layout_preset"`
	UpdateInterval  string                 `json:"update_interval"`
	GraphStyle      string                 `json:"graph_style"`
	PanelStates     map[string]bool        `json:"panel_states"`
	GradientEnabled bool                   `json:"gradient_enabled"`
	ShowLegend      bool                   `json:"show_legend"`
	DashboardLayout *DashboardLayout       `json:"dashboard_layout,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

// NewUI creates a new terminal UI
func NewUI(networkMonitor *netcap.NetworkMonitor) *UI {
	ui := &UI{
		app:            tview.NewApplication(),
		networkMonitor: networkMonitor,
		updateInterval: 1 * time.Second,
		stopChan:       make(chan struct{}),
		sortBy:         "bytes",
		sortAscending:  false,
		theme:          Themes["Dark+"],
		styleName:      "Standard",
		geoCache:       make(map[string]*GeoLocation),
		currentLayout:  0,
		layoutPresets:  []string{"Default", "Compact", "Detailed", "Minimal"},
		graphStyle:     graph.StyleBraille,
		markedConnections: make(map[string]bool),
		connectionHistory: make(map[string][]float64),
		borderStyle:    "Single",
		borderAnimation: "None",
	}

	ui.initComponents()
	ui.setupUI()
	
	// Enable mouse support
	ui.app.EnableMouse(true)
	ui.setupMouseHandlers()
	// Initialize pie-chart panels
	ui.servicePieView = tview.NewTextView().SetDynamicColors(true)
	ui.servicePieView.SetBorder(true).SetBorderColor(ui.theme.PieBorderColor).SetTitleColor(ui.theme.PieTitleColor).SetTitle(i18n.T("service_usage_pie"))
	ui.protocolPieView = tview.NewTextView().SetDynamicColors(true)
	ui.protocolPieView.SetBorder(true).SetBorderColor(ui.theme.PieBorderColor).SetTitleColor(ui.theme.PieTitleColor).SetTitle(i18n.T("protocol_usage_pie"))
	ui.securePieView = tview.NewTextView().SetDynamicColors(true)
	ui.securePieView.SetBorder(true).SetBorderColor(ui.theme.PieBorderColor).SetTitleColor(ui.theme.PieTitleColor).SetTitle(i18n.T("secure_nonsecure_pie"))
	// Interface counters page as table
	ui.ifaceStatsView = tview.NewTable().SetBorders(false)
	ui.ifaceStatsView.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitleColor(ui.theme.TitleColor).SetTitle(i18n.T("interface_counters"))
	ui.ifaceStatsView.SetFixed(1, 0)
	// Packet size histogram view
	ui.histView = tview.NewTextView().SetDynamicColors(true)
	ui.histView.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitleColor(ui.theme.TitleColor).SetTitle(i18n.T("packet_size_histogram"))
	// HTTP/DNS summary view
	ui.dnsHttpView = tview.NewTextView().SetDynamicColors(true)
	ui.dnsHttpView.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitleColor(ui.theme.TitleColor).SetTitle(i18n.T("http_dns_summary"))
	// Geo mapping view: will list remote IPs and country codes
	ui.geoView = tview.NewTable().SetBorders(false)
	ui.geoView.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitleColor(ui.theme.TitleColor).SetTitle(i18n.T("geo_mapping"))
	ui.geoView.SetFixed(1, 0)
	// Geo map view for ASCII world map
	ui.geoMapView = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	ui.geoMapView.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitleColor(ui.theme.TitleColor).SetTitle(i18n.T("world_map"))
	// Help view
	ui.helpView = tview.NewTextView().SetDynamicColors(true).SetWrap(true)
	ui.helpView.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitleColor(ui.theme.TitleColor).SetTitle(i18n.T("help"))
	// Raw packet hex view
	ui.rawView = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	ui.rawView.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitleColor(ui.theme.TitleColor).SetTitle(i18n.T("raw_packet"))
	// Plugin view
	ui.pluginView = tview.NewTextView().SetDynamicColors(true).SetWrap(true)
	ui.pluginView.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitleColor(ui.theme.TitleColor).SetTitle(i18n.T("plugins"))
	// Define panel layout (interfaces column + data panels)
	ui.panels = []*panel{
		{id: "interfaces", primitive: ui.interfaceList, visible: true, row: 0, col: 0, rowSpan: 4, colSpan: 1},
		{id: "stats", primitive: ui.statsView, visible: true, row: 0, col: 1, rowSpan: 1, colSpan: 1},
		{id: "traffic", primitive: ui.trafficGraph, visible: true, row: 0, col: 2, rowSpan: 1, colSpan: 1},
		{id: "protocol", primitive: ui.protocolView, visible: true, row: 0, col: 3, rowSpan: 1, colSpan: 1},
		{id: "servicePie", primitive: ui.servicePieView, visible: true, row: 1, col: 1, rowSpan: 1, colSpan: 1},
		{id: "protocolPie", primitive: ui.protocolPieView, visible: true, row: 1, col: 2, rowSpan: 1, colSpan: 1},
		{id: "securePie", primitive: ui.securePieView, visible: true, row: 1, col: 3, rowSpan: 1, colSpan: 1},
		{id: "connections", primitive: ui.connectionTable, visible: true, row: 2, col: 1, rowSpan: 1, colSpan: 3},
		{id: "details", primitive: ui.detailView, visible: true, row: 3, col: 1, rowSpan: 1, colSpan: 3},
	}
	// Build the initial grid
	ui.rebuildLayout()
	return ui
}

// RegisterPlugin registers a plugin with the UI
func (ui *UI) RegisterPlugin(name, description string) {
	plugin := PluginInfo{
		Name:        name,
		Description: description,
		Output:      []string{},
		LastUpdate:  time.Now(),
		Status:      "Active",
	}
	ui.plugins = append(ui.plugins, plugin)
}

// UpdatePluginOutput updates the output for a specific plugin
func (ui *UI) UpdatePluginOutput(name string, output string) {
	for i := range ui.plugins {
		if ui.plugins[i].Name == name {
			ui.plugins[i].Output = append(ui.plugins[i].Output, output)
			// Keep only last 100 lines
			if len(ui.plugins[i].Output) > 100 {
				ui.plugins[i].Output = ui.plugins[i].Output[len(ui.plugins[i].Output)-100:]
			}
			ui.plugins[i].LastUpdate = time.Now()
			break
		}
	}
}

// SetPluginStatus updates the status of a plugin
func (ui *UI) SetPluginStatus(name string, status string) {
	for i := range ui.plugins {
		if ui.plugins[i].Name == name {
			ui.plugins[i].Status = status
			break
		}
	}
}

// initComponents initializes all UI primitives
func (ui *UI) initComponents() {
	// Interface list
	ui.interfaceList = tview.NewList().ShowSecondaryText(false)
	ui.interfaceList.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitle(i18n.T("interfaces"))
	// Stats view
	ui.statsView = tview.NewTextView().SetDynamicColors(true)
	ui.statsView.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitle(i18n.T("network_statistics"))
	// Traffic graph
	ui.trafficGraph = graph.NewMultiGraph()
	ui.trafficGraph.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitle(i18n.T("network_traffic"))
	// Network graph widget
	ui.networkGraph = graph.NewGraphWidget()
	ui.networkGraph.SetTitle(i18n.T("bandwidth"))
	ui.networkGraph.SetColor(ui.theme.PrimaryColor)
	ui.networkGraph.SetSecondaryColor(ui.theme.SecondaryColor)
	ui.networkGraph.SetLabels("In", "Out")
	ui.networkGraph.SetUnit("B/s")
	ui.networkGraph.SetDataFunc(ui.getNetworkRates)
	ui.networkGraph.SetSampleInterval(1 * time.Second)
	ui.networkGraph.SetHistoryDuration(2 * time.Minute)
	ui.networkGraph.SetStyle(ui.graphStyle)
	ui.trafficGraph.AddGraph(ui.networkGraph)
	// CPU & Memory usage graph widget
	ui.cpuMemGraph = graph.NewGraphWidget()
	ui.cpuMemGraph.SetTitle(i18n.T("cpu_mem"))
	ui.cpuMemGraph.SetColor(ui.theme.PrimaryColor)
	ui.cpuMemGraph.SetSecondaryColor(ui.theme.SecondaryColor)
	ui.cpuMemGraph.SetLabels("CPU%", "Mem%")
	ui.cpuMemGraph.SetUnit("%")
	ui.cpuMemGraph.SetDataFunc(ui.getCPUMemory)
	ui.cpuMemGraph.SetSampleInterval(1 * time.Second)
	ui.cpuMemGraph.SetHistoryDuration(2 * time.Minute)
	ui.cpuMemGraph.SetStyle(ui.graphStyle)
	ui.trafficGraph.AddGraph(ui.cpuMemGraph)
	// Protocol view
	ui.protocolView = tview.NewTextView().SetDynamicColors(true)
	ui.protocolView.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitle(i18n.T("protocols"))
	// Connection table
	ui.connectionTable = tview.NewTable().SetBorders(false)
	ui.connectionTable.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitle(i18n.T("connections"))
	ui.connectionTable.SetSelectable(true, false)
	// Detail view
	ui.detailView = tview.NewTextView().SetDynamicColors(true)
	ui.detailView.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitle(i18n.T("connection_details"))
	// Status bar
	ui.statusBar = tview.NewTextView().SetDynamicColors(true)
	ui.statusBar.SetTextAlign(tview.AlignCenter)
	ui.statusBar.SetBackgroundColor(ui.theme.StatusBarBgColor)
}

// setupUI initializes the UI components
func (ui *UI) setupUI() {
	// Create the pages for different views
	ui.pages = tview.NewPages()

	// Set up key bindings
	ui.setupKeyBindings()

	// Set the root and focus
	ui.app.SetRoot(ui.pages, true)
	// Focus on interface list by default
	ui.app.SetFocus(ui.interfaceList)
}

// setupKeyBindings configures keyboard shortcuts
func (ui *UI) setupKeyBindings() {
	ui.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		// Global key bindings
		switch event.Key() {
		case tcell.KeyEscape:
			// If on a secondary page, return to main
			if ui.pages.HasPage("help") {
				name, _ := ui.pages.GetFrontPage()
				if name == "help" {
					ui.pages.SwitchToPage("main")
					return nil
				}
			}
		case tcell.KeyTab:
			// Cycle focus between panels
			if ui.interfaceList.HasFocus() {
				ui.app.SetFocus(ui.connectionTable)
			} else if ui.connectionTable.HasFocus() {
				ui.app.SetFocus(ui.interfaceList)
			} else {
				ui.app.SetFocus(ui.interfaceList)
			}
			return nil
		}

		// Handle runes - btop-style single key shortcuts
		switch event.Rune() {
		case 'q', 'Q':
			// Show exit menu instead of immediate quit
			ui.showExitMenu()
			return nil
		case '?', 'h', 'H':
			// Help screen
			name, _ := ui.pages.GetFrontPage()
			if name == "help" {
				ui.pages.SwitchToPage("main")
			} else {
				ui.showHelpPage()
			}
			return nil
		case 'o', 'O':
			// Options/settings menu - only show on main page
			if ui.pages != nil {
				if name, _ := ui.pages.GetFrontPage(); name == "main" {
					ui.showOptionsMenu()
				}
			}
			return nil
		case 'p', 'P':
			// Cycle through layout presets
			ui.cycleLayoutPreset()
			return nil
		case '+', '=':
			// Increase update speed
			ui.decreaseUpdateInterval()
			return nil
		case '-', '_':
			// Decrease update speed
			ui.increaseUpdateInterval()
			return nil
		case 'r':
			// Force refresh
			ui.updateData()
			return nil
		case 's', 'S':
			// Sort options
			ui.showSortOptions()
			return nil
		case 'f', 'F':
			// Filter
			ui.showFilterInput()
			return nil
		case 'b', 'B':
			// BPF filter
			ui.showBpfInput()
			return nil
		case 'n':
			// Next interface
			ui.selectNextInterface()
			return nil
		case 'N':
			// Previous interface
			ui.selectPreviousInterface()
			return nil
		case 't', 'T':
			// Toggle graph style
			ui.cycleGraphStyle()
			return nil
		case 'e', 'E':
			// Export data
			ui.showExportMenu()
			return nil
		case 'u', 'U':
			// UI Profiles menu
			ui.showProfilesMenu()
			return nil
		case 'c', 'C':
			// Clear filters
			ui.clearFilters()
			return nil
		case ' ':
			// Pause/resume updates
			ui.togglePause()
			return nil
		case 'R':
			// Start/stop recording
			ui.toggleRecording()
			return nil
		case 'L':
			// Load and replay session
			ui.showReplayMenu()
			return nil
		case 'G':
			// Show plugins view
			ui.showPluginsPage()
			return nil
		case '&':
			// Show border styles preview
			ui.showBorderStylesPreview()
			return nil
		// Legacy shortcuts for specific pages
		case 'i':
			ui.showIfaceStatsPage()
			return nil
		case 'd':
			// Dashboard menu
			ui.showDashboardMenu()
			return nil
		case 'g':
			ui.showGeoPage()
			return nil
		}

		// Panel toggle keys 0–9 (0 = interfaces)
		switch event.Rune() {
		case '0': ui.togglePanel("interfaces")
		case '1': ui.togglePanel("stats")
		case '2': ui.togglePanel("traffic")
		case '3': ui.togglePanel("protocol")
		case '4': ui.togglePanel("servicePie")
		case '5': ui.togglePanel("protocolPie")
		case '6': ui.togglePanel("securePie")
		case '7': ui.togglePanel("connections")
		case '8': ui.togglePanel("details")
		case '9': ui.togglePanel("packets")
		}

		return event
	})

	// Interface list selection changed
	ui.interfaceList.SetChangedFunc(func(index int, mainText, secondaryText string, shortcut rune) {
		if index >= 0 {
			ui.selectedIface = mainText
			ui.updateData()
		}
	})

	// Connection table selection changed
	ui.connectionTable.SetSelectionChangedFunc(func(row, column int) {
		if row > 0 && row-1 < len(ui.connections) {
			ui.selectedConnection = ui.connections[row-1]
			// Update details in a safe way
			go ui.app.QueueUpdateDraw(func() {
				ui.showConnectionDetails(ui.selectedConnection)
			})
		} else {
			ui.selectedConnection = nil
			go ui.app.QueueUpdateDraw(func() {
				ui.detailView.SetText("")
			})
		}
	})
	
	// Add connection table keyboard shortcuts
	ui.connectionTable.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if ui.selectedConnection == nil {
			return event
		}
		
		switch event.Key() {
		case tcell.KeyEnter:
			// Show detailed packet view
			ui.showConnectionPacketsPage()
			return nil
		case tcell.KeyDelete:
			// Show kill connection dialog
			ui.showKillConnectionDialog()
			return nil
		}
		
		switch event.Rune() {
		case 'k', 'K':
			// Kill connection
			ui.showKillConnectionDialog()
			return nil
		case 'e', 'E':
			// Export connection data
			ui.showConnectionExportMenu()
			return nil
		case 'x', 'X':
			// Mark/unmark connection
			ui.toggleConnectionMark()
			return nil
		case 'a', 'A':
			// Select all connections
			ui.selectAllConnections()
			return nil
		}
		
		return event
	})
}

// updateAnimationTicker manages the animation update ticker
func (ui *UI) updateAnimationTicker() {
	// Stop existing ticker if any
	if ui.animationTicker != nil {
		ui.animationTicker.Stop()
		ui.animationTicker = nil
	}
	
	// Start new ticker if animation is enabled
	if ui.borderAnimation != "None" && ui.borderAnimation != "" {
		ui.animationTicker = time.NewTicker(100 * time.Millisecond)
		go func() {
			for range ui.animationTicker.C {
				ui.animationFrame++
				ui.app.QueueUpdateDraw(func() {
					if ui.mainGrid != nil {
						ui.mainGrid.SetAnimationFrame(ui.animationFrame)
					}
				})
			}
		}()
	}
}

// rebuildLayout re-constructs the main page grid based on panel settings
func (ui *UI) rebuildLayout() {
    grid := NewStyledGrid().
        SetBorders(true).
        SetBorderStyle(ui.borderStyle).
        SetBorderColor(ui.theme.BorderColor).
        SetAnimation(ui.borderAnimation).
        SetAnimationFrame(ui.animationFrame)
    
    // Store reference to main grid for animation updates
    ui.mainGrid = grid

    // determine if interfaces panel is visible
    ifaceVisible := false
    for _, p := range ui.panels {
        if p.id == "interfaces" && p.visible {
            ifaceVisible = true
            break
        }
    }

    // dynamic tiling: identify visible non-interface rows
    rowsSet := map[int]bool{}
    for _, p := range ui.panels {
        if p.visible && p.id != "interfaces" {
            rowsSet[p.row] = true
        }
    }
    // sort and collect rows
    visibleRows := make([]int, 0, len(rowsSet))
    for r := range rowsSet {
        visibleRows = append(visibleRows, r)
    }
    sort.Ints(visibleRows)
    totalRows := len(visibleRows)
    if totalRows == 0 {
        totalRows = 1
    }
    // count regular panels per row
    colCounts := map[int]int{}
    for _, p := range ui.panels {
        if p.visible && p.id != "interfaces" && p.colSpan == 1 {
            colCounts[p.row]++
        }
    }
    maxCols := 0
    for _, c := range colCounts {
        if c > maxCols {
            maxCols = c
        }
    }
    if maxCols == 0 {
        maxCols = 1
    }
    // define grid sizes
    rows := make([]int, totalRows)
    grid.SetRows(rows...)
    dataOffset := 1
    if !ifaceVisible {
        dataOffset = 0
    }
    cols := make([]int, maxCols+dataOffset)
    if ifaceVisible {
        cols[0] = 20
        for i := 1; i < len(cols); i++ {
            cols[i] = 0
        }
    } else {
        for i := 0; i < len(cols); i++ {
            cols[i] = 0
        }
    }
    grid.SetColumns(cols...)

    // place panels
    for _, p := range ui.panels {
        if !p.visible {
            continue
        }
        if p.id == "interfaces" {
            if ifaceVisible {
                // span all rows in first col
                grid.AddItem(p.primitive, 0, 0, totalRows, 1, 0, 0, true)
            }
            continue
        }
        // map original row to new index
        newRow := 0
        for i, r := range visibleRows {
            if r == p.row {
                newRow = i
                break
            }
        }
        if p.colSpan > 1 {
            // full-width panels except interfaces
            grid.AddItem(p.primitive, newRow, dataOffset, p.rowSpan, maxCols, 0, 0, true)
        } else {
            // tile single-col panels
            idx := 0
            for _, q := range ui.panels {
                if !q.visible || q.id == "interfaces" || q.colSpan > 1 || q.row != p.row {
                    continue
                }
                if q.id == p.id {
                    break
                }
                idx++
            }
            grid.AddItem(p.primitive, newRow, dataOffset+idx, p.rowSpan, 1, 0, 0, true)
        }
    }
    ui.pages.RemovePage("main")
    ui.pages.AddPage("main", grid, true, true)
    ui.app.SetRoot(ui.pages, true)
}

// togglePanel flips visibility of the named panel and rebuilds layout
func (ui *UI) togglePanel(id string) {
	for _, p := range ui.panels {
		if p.id == id {
			p.visible = !p.visible
			break
		}
	}
	ui.rebuildLayout()
}

// updateData refreshes all UI components with current data
func (ui *UI) updateData() {
	// Start capturing on the selected interface if not already
	if ui.selectedIface != "" {
		err := ui.networkMonitor.StartCapture(ui.selectedIface)
		if err != nil && !strings.Contains(err.Error(), "already capturing") {
			ui.showError(fmt.Sprintf("Error starting capture: %v", err))
		}
		// Apply BPF filter if set
		if ui.bpfString != "" {
			_ = ui.networkMonitor.SetBpfFilter(ui.selectedIface, ui.bpfString)
		}
	}

	ui.updateStatsView()
	ui.updateConnectionHistory()
	ui.updateConnectionTable()
	ui.updateProtocolView()
	ui.updatePieCharts()
	
	// Record snapshot if recording
	if ui.recording {
		ui.recordSnapshot()
	}
	
	// Auto-refresh packets page if visible
	if name, _ := ui.pages.GetFrontPage(); name == "packets" {
		ui.pages.RemovePage("packets")
		ui.showPacketBufferPage()
	}
	
	// We don't need to manually add data points here anymore
	// The graph widget's goroutine will handle that
}

// updatePieCharts computes counts and updates ASCII pie-chart panels
func (ui *UI) updatePieCharts() {
	buf := ui.networkMonitor.GetPacketBuffer()
	total := len(buf)
	svcCounts := make(map[string]int)
	protoCounts := make(map[string]int)
	secureCounts := map[string]int{"Secure": 0, "NonSecure": 0}
	for _, p := range buf {
		svcCounts[p.Service]++
		protoCounts[p.Protocol]++
		if p.Service == "HTTPS" {
			secureCounts["Secure"]++
		} else {
			secureCounts["NonSecure"]++
		}
	}
	svcChart := renderStackedPie(ui.servicePieView, svcCounts, total)
	ui.servicePieView.SetText(svcChart)
	ui.servicePieView.ScrollToBeginning()
	protoChart := renderStackedPie(ui.protocolPieView, protoCounts, total)
	ui.protocolPieView.SetText(protoChart)
	ui.protocolPieView.ScrollToBeginning()
	secChart := renderStackedPie(ui.securePieView, secureCounts, total)
	ui.securePieView.SetText(secChart)
	ui.securePieView.ScrollToBeginning()
}

var pieColors = []string{
	"[green]", "[blue]", "[magenta]", "[yellow]", "[red]",
	"[cyan]", "[white]", "[orange]", "[purple]", "[gray]",
}

// renderStackedPie renders pie and legend one above the other, fitting the TextView
func renderStackedPie(tv *tview.TextView, counts map[string]int, total int) string {
	legend := buildLegend(counts, total)
	legendLines := len(strings.Split(strings.TrimRight(legend, "\n"), "\n"))
	_, _, width, height := tv.GetInnerRect()
	// available height for chart area (excluding legend) and minimal width
	chartArea := height - legendLines
	if chartArea < 5 || width < 8 {
		// not enough space to draw a circle
		return legend
	}
	// compute max radius by height (chart uses 2*r + 3 lines)
	maxRadiusH := (chartArea - 3) / 2
	// compute max radius by width (chart interior requires 4*r + 4 chars)
	maxRadiusW := (width - 4) / 4
	// choose the smaller radius
	r := maxRadiusH
	if maxRadiusW < r {
		r = maxRadiusW
	}
	if r < 1 {
		r = 1
	}
	chart := renderTermPieWithRadius(counts, total, r)
	return chart + legend
}

// renderTermPieWithRadius renders a pie chart with a specified radius
func renderTermPieWithRadius(counts map[string]int, total int, radius int) string {
	// handle no data
	if total == 0 || len(counts) == 0 {
		return "\n   [gray]No data\n"
	}
	// compute slices
	type slice struct{ start, end float64; color string }
	keys := make([]string, 0, len(counts))
	for k := range counts { keys = append(keys, k) }
	sort.Strings(keys)
	var slices []slice
	current := -math.Pi/2
	if len(keys) == 1 {
		// single slice: fill whole pie
		slices = append(slices, slice{-math.Pi, math.Pi, pieColors[0]})
	} else {
		for i, k := range keys {
			frac := 0.0
			if total > 0 { frac = float64(counts[k]) / float64(total) }
			span := frac * 2 * math.Pi
			slices = append(slices, slice{current, current + span, pieColors[i%len(pieColors)]})
			current += span
		}
	}
	// draw grid
	var sb strings.Builder
	sb.WriteString("[gray]+" + strings.Repeat("-", radius*4) + "+\n")
	for y := -radius; y <= radius; y++ {
		line := ""
		for x := -radius; x <= radius; x++ {
			dx := float64(x) / float64(radius)
			dy := float64(y) / float64(radius)
			if dx*dx+dy*dy > 1.0 {
				line += "  "
				continue
			}
			// center label for single-slice
			ang := math.Atan2(dy, dx)
			col := "[white]"
			for i, s := range slices {
				if (s.start <= s.end && ang >= s.start && ang < s.end) ||
					(s.start > s.end && (ang >= s.start || ang < s.end)) {
					col = pieColors[i%len(pieColors)]
					break
				}
			}
			line += col + "@ "
		}
		// Pad line to fixed width
		for len(line) < (radius*2+1)*2 { line += " " }
		sb.WriteString("|" + line + "|\n")
	}
	sb.WriteString("[gray]+" + strings.Repeat("-", radius*4) + "+\n")
	return sb.String()
}

// buildLegend builds a legend for a pie chart: colored label, percent, and count
func buildLegend(counts map[string]int, total int) string {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	// Collect legend lines and find max width
	lines := make([]string, len(keys))
	maxWidth := 0
	for i, k := range keys {
		v := counts[k]
		perc := 0
		if total > 0 { perc = v * 100 / total }
		color := pieColors[i%len(pieColors)]
		line := fmt.Sprintf("%s%s %d%% [%d]", color, k, perc, v)
		lines[i] = line
		if len(line) > maxWidth {
			maxWidth = len(line)
		}
	}
	// Right-align all lines
	var sb strings.Builder
	for _, line := range lines {
		pad := maxWidth - len(line)
		sb.WriteString(strings.Repeat(" ", pad) + line + "\n")
	}
	return sb.String()
}

// showSortOptions displays a modal for sorting options
func (ui *UI) showSortOptions() {
    modal := tview.NewModal().SetText(i18n.T("sort_connections_by")).
        AddButtons([]string{i18n.T("bytes"), i18n.T("packets"), i18n.T("last_seen"), i18n.T("cancel")}).
        SetDoneFunc(func(_ int, label string) {
            if label != i18n.T("cancel") {
                switch label {
                case i18n.T("bytes"):
                    ui.sortBy = "bytes"
                case i18n.T("packets"):
                    ui.sortBy = "packets"
                case i18n.T("last_seen"):
                    ui.sortBy = "time"
                }
                ui.sortAscending = !ui.sortAscending
                ui.updateConnectionTable()
            }
            ui.pages.SwitchToPage("main")
        })
    ui.pages.AddPage("sort", modal, true, true)
}

// showFilterInput displays an input form for filtering connections
func (ui *UI) showFilterInput() {
    ui.showAdvancedFilterDialog()
}

// showBpfInput displays an input form for setting BPF filter
func (ui *UI) showBpfInput() {
    form := tview.NewForm().
        AddInputField(i18n.T("bpf_filter"), ui.bpfString, 40, nil, func(text string) { ui.bpfString = text }).
        AddButton(i18n.T("apply"), func() { _ = ui.networkMonitor.SetBpfFilter(ui.selectedIface, ui.bpfString); ui.pages.SwitchToPage("main") }).
        AddButton(i18n.T("clear"), func() { ui.bpfString = ""; _ = ui.networkMonitor.SetBpfFilter(ui.selectedIface, ""); ui.pages.SwitchToPage("main") }).
        AddButton(i18n.T("cancel"), func() { ui.pages.SwitchToPage("main") })
    form.SetBorder(true).SetTitle(i18n.T("bpf_filter")).SetTitleAlign(tview.AlignCenter)
    ui.pages.AddPage("bpf", form, true, true)
}

// showPacketBufferPage displays recent captured packets
func (ui *UI) showPacketBufferPage() {
    ui.pages.RemovePage("packets")
    packets := ui.networkMonitor.GetPacketBuffer()
    table := tview.NewTable().SetBorders(false)
    table.SetSelectable(true, false).SetFixed(1, 0)
    table.Select(1, 0)
    table.SetBorder(true).SetTitle(i18n.T("captured_packets"))
    headers := []string{i18n.T("time"), i18n.T("source"), i18n.T("destination"), i18n.T("proto"), i18n.T("service"), i18n.T("length")}
    for i, h := range headers {
        table.SetCell(0, i, tview.NewTableCell(h).
            SetTextColor(tcell.ColorYellow).SetSelectable(false))
    }
    for r, p := range packets {
        row := r + 1
        table.SetCell(row, 0, tview.NewTableCell(p.Timestamp.Format("15:04:05")))
        table.SetCell(row, 1, tview.NewTableCell(fmt.Sprintf("%s:%d", p.SrcIP, p.SrcPort)))
        table.SetCell(row, 2, tview.NewTableCell(fmt.Sprintf("%s:%d", p.DstIP, p.DstPort)))
        // protocol color
        protoColor := ui.theme.SecondaryColor
        switch p.Protocol {
        case "TCP": protoColor = tcell.ColorGreen
        case "UDP": protoColor = tcell.ColorBlue
        case "ICMP": protoColor = tcell.ColorFuchsia
        }
        table.SetCell(row, 3, tview.NewTableCell(p.Protocol).SetTextColor(protoColor))
        table.SetCell(row, 4, tview.NewTableCell(p.Service))
        table.SetCell(row, 5, tview.NewTableCell(fmt.Sprintf("%d", p.Length)))
    }
    table.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
        switch event.Key() {
        case tcell.KeyEscape:
            ui.pages.SwitchToPage("main")
            return nil
        case tcell.KeyEnter:
            row, _ := table.GetSelection()
            if row > 0 {
                ui.showRawPacketPage(row-1)
            }
            return nil
        }
        return event
    })
    ui.pages.AddPage("packets", table, true, true)
    ui.app.SetFocus(table)
}

// showIfaceStatsPage displays interface counters and errors/drops
func (ui *UI) showIfaceStatsPage() {
    ui.pages.RemovePage("ifaceStats")
    table := ui.ifaceStatsView
    table.Clear()
    // Header row
    headers := []string{i18n.T("interface"), i18n.T("in_bytes_packets"), i18n.T("out_bytes_packets"), i18n.T("pcap_recv"), i18n.T("pcap_drop"), i18n.T("pcap_ifdrop")}
    for i, h := range headers {
        table.SetCell(0, i, tview.NewTableCell(h).
            SetTextColor(tcell.ColorYellow).
            SetSelectable(false))
    }
    // Data rows
    ifaces, _ := netcap.GetInterfaces()
    statsMap := ui.networkMonitor.GetInterfaceStats()
    for r, iface := range ifaces {
        name := iface.Name
        ifStats, ok := statsMap[name]
        if !ok {
            ifStats = &netcap.InterfaceStats{Name: name}
        }
        rec, dr, ifdr := 0, 0, 0
        if pStats, err := ui.networkMonitor.GetPcapStats(name); err == nil {
            rec = pStats.PacketsReceived
            dr = pStats.PacketsDropped
            ifdr = pStats.PacketsIfDropped
        }
        row := r + 1
        table.SetCell(row, 0, tview.NewTableCell(name))
        table.SetCell(row, 1, tview.NewTableCell(fmt.Sprintf("%s/%d", utils.FormatBytes(ifStats.BytesIn), ifStats.PacketsIn)))
        table.SetCell(row, 2, tview.NewTableCell(fmt.Sprintf("%s/%d", utils.FormatBytes(ifStats.BytesOut), ifStats.PacketsOut)))
        table.SetCell(row, 3, tview.NewTableCell(fmt.Sprintf("%d", rec)))
        table.SetCell(row, 4, tview.NewTableCell(fmt.Sprintf("%d", dr)))
        table.SetCell(row, 5, tview.NewTableCell(fmt.Sprintf("%d", ifdr)))
    }
    table.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
        if event.Key() == tcell.KeyEscape {
            ui.pages.SwitchToPage("main")
            return nil
        }
        return event
    })
    ui.pages.AddPage("ifaceStats", table, true, true)
    ui.app.SetFocus(table)
}

// showHistPage displays a packet-size histogram
func (ui *UI) showHistPage() {
    ui.pages.RemovePage("hist")
    buf := ui.networkMonitor.GetPacketBuffer()
    var sb strings.Builder
    if len(buf) == 0 {
        sb.WriteString("[yellow]" + i18n.T("no_packets_captured") + "\n")
    } else {
        buckets := []int{64, 128, 256, 512, 1024, 1500}
        labels := []string{i18n.T("lt_64"), i18n.T("64_127"), i18n.T("128_255"), i18n.T("256_511"), i18n.T("512_1023"), i18n.T("gte_1024")}
        counts := make([]int, len(buckets))
        for _, p := range buf {
            l := int(p.Length)
            idx := len(buckets) - 1
            for i, th := range buckets {
                if l < th { idx = i; break }
            }
            counts[idx]++
        }
        maxCount := 0
        for _, c := range counts { if c > maxCount { maxCount = c } }
        barWidth := 50
        for i, label := range labels {
            bar := ""
            if maxCount > 0 {
                w := int(math.Round(float64(counts[i]) * float64(barWidth) / float64(maxCount)))
                bar = strings.Repeat("█", w)
            }
            sb.WriteString(fmt.Sprintf("%-10s |%s (%d)\n", label, bar, counts[i]))
        }
    }
    ui.histView.SetText(sb.String())
    ui.histView.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
        if event.Key() == tcell.KeyEscape {
            ui.pages.SwitchToPage("main")
            return nil
        }
        return event
    })
    ui.pages.AddPage("hist", ui.histView, true, true)
    ui.app.SetFocus(ui.histView)
}

// showDnsHttpPage displays HTTP and DNS packet counts
func (ui *UI) showDnsHttpPage() {
    ui.pages.RemovePage("dnsHttp")
    buf := ui.networkMonitor.GetPacketBuffer()
    httpCount, httpsCount, dnsCount := 0, 0, 0
    for _, p := range buf {
        switch p.Service {
        case "HTTP": httpCount++
        case "HTTPS": httpsCount++
        case "DNS": dnsCount++
        }
    }
    text := fmt.Sprintf(
        "[green]" + i18n.T("http") + ":[white] %d\n"+
        "[green]" + i18n.T("https") + ":[white] %d\n"+
        "[green]" + i18n.T("dns") + ":[white] %d\n",
        httpCount, httpsCount, dnsCount,
    )
    ui.dnsHttpView.SetText(text)
    ui.dnsHttpView.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
        if event.Key() == tcell.KeyEscape {
            ui.pages.SwitchToPage("main")
            return nil
        }
        return event
    })
    ui.pages.AddPage("dnsHttp", ui.dnsHttpView, true, true)
    ui.app.SetFocus(ui.dnsHttpView)
}

// showGeoPage displays enhanced geographic visualization
func (ui *UI) showGeoPage() {
    ui.pages.RemovePage("geo")
    
    // Create a flex container for map and table
    flex := tview.NewFlex().SetDirection(tview.FlexRow)
    
    // Update geo data
    ui.updateGeoData()
    
    // Add world map view (takes up more space)
    flex.AddItem(ui.geoMapView, 0, 3, false)
    
    // Add detailed geo table
    flex.AddItem(ui.geoView, 0, 2, true)
    
    // Set up input capture for the flex container
    flex.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
        switch event.Key() {
        case tcell.KeyEscape:
            ui.pages.SwitchToPage("main")
            return nil
        case tcell.KeyTab:
            // Toggle focus between map and table
            if ui.geoView.HasFocus() {
                ui.app.SetFocus(ui.geoMapView)
            } else {
                ui.app.SetFocus(ui.geoView)
            }
            return nil
        }
        
        switch event.Rune() {
        case 'r', 'R':
            // Refresh geo data
            ui.clearGeoCache()
            ui.updateGeoData()
            return nil
        }
        
        return event
    })
    
    ui.pages.AddPage("geo", flex, true, true)
    ui.app.SetFocus(ui.geoView)
}

// updateGeoData updates both the map and table with current connection data
func (ui *UI) updateGeoData() {
    // Clear views
    ui.geoView.Clear()
    ui.geoMapView.Clear()
    
    if ui.selectedIface == "" {
        fmt.Fprintf(ui.geoMapView, "[yellow]No interface selected[white]")
        return
    }
    
    // Gather connections
    conns := ui.networkMonitor.GetConnections(ui.selectedIface)
    ipConnections := make(map[string]int)
    ipTraffic := make(map[string]uint64)
    
    for _, c := range conns {
        // Determine remote IP
        var remoteIP string
        if ui.networkMonitor.IsLocalAddress(c.SrcIP.String()) {
            remoteIP = c.DstIP.String()
        } else {
            remoteIP = c.SrcIP.String()
        }
        
        // Skip local addresses
        if ui.networkMonitor.IsLocalAddress(remoteIP) {
            continue
        }
        
        ipConnections[remoteIP]++
        ipTraffic[remoteIP] += c.Size
    }
    
    // Fetch geo data for IPs
    locations := make([]*GeoLocation, 0)
    countryCounts := make(map[string]int)
    countryTraffic := make(map[string]uint64)
    
    for ip := range ipConnections {
        loc := ui.getGeoLocation(ip)
        if loc != nil {
            locations = append(locations, loc)
            countryCounts[loc.CountryCode] += ipConnections[ip]
            countryTraffic[loc.CountryCode] += ipTraffic[ip]
        }
    }
    
    // Sort locations by connection count
    sort.Slice(locations, func(i, j int) bool {
        return ipConnections[locations[i].Country] > ipConnections[locations[j].Country]
    })
    
    // Update world map
    worldMap := NewWorldMap()
    maxCount := 0
    for _, count := range countryCounts {
        if count > maxCount {
            maxCount = count
        }
    }
    
    mapStr := worldMap.RenderWithColors(countryCounts, maxCount)
    fmt.Fprint(ui.geoMapView, mapStr)
    fmt.Fprintf(ui.geoMapView, "\n%s", GetMapLegend())
    
    // Update table with detailed information
    headers := []string{"IP", "Country", "City", "Region", "ISP/Org", "Connections", "Traffic"}
    for i, h := range headers {
        ui.geoView.SetCell(0, i, tview.NewTableCell(h).
            SetTextColor(ui.theme.PrimaryColor).
            SetSelectable(false).
            SetAlign(tview.AlignCenter))
    }
    
    // Add data rows
    row := 1
    addedIPs := make(map[string]bool)
    
    for _, loc := range locations {
        // Find all IPs for this location
        for ip, count := range ipConnections {
            ipLoc := ui.getGeoLocation(ip)
            if ipLoc == nil || addedIPs[ip] {
                continue
            }
            
            if ipLoc.Country == loc.Country && ipLoc.City == loc.City {
                ui.geoView.SetCell(row, 0, tview.NewTableCell(ip))
                ui.geoView.SetCell(row, 1, tview.NewTableCell(fmt.Sprintf("%s %s", ipLoc.CountryCode, ipLoc.Country)))
                ui.geoView.SetCell(row, 2, tview.NewTableCell(ipLoc.City))
                ui.geoView.SetCell(row, 3, tview.NewTableCell(ipLoc.Region))
                
                // Show ISP or Org
                ispOrg := ipLoc.ISP
                if ispOrg == "" {
                    ispOrg = ipLoc.Org
                }
                if len(ispOrg) > 30 {
                    ispOrg = ispOrg[:27] + "..."
                }
                ui.geoView.SetCell(row, 4, tview.NewTableCell(ispOrg))
                
                ui.geoView.SetCell(row, 5, tview.NewTableCell(fmt.Sprintf("%d", count)).
                    SetAlign(tview.AlignRight))
                ui.geoView.SetCell(row, 6, tview.NewTableCell(utils.FormatBytes(ipTraffic[ip])).
                    SetAlign(tview.AlignRight))
                
                addedIPs[ip] = true
                row++
            }
        }
    }
    
    // Add summary at the bottom
    fmt.Fprintf(ui.geoMapView, "\n\n[yellow]Summary:[white] %d unique IPs from %d countries", 
        len(ipConnections), len(countryCounts))
}

// getGeoLocation fetches or retrieves cached geo location for an IP
func (ui *UI) getGeoLocation(ip string) *GeoLocation {
    // Check cache
    if loc, ok := ui.geoCache[ip]; ok {
        // Cache for 24 hours
        if time.Since(loc.LastUpdate) < 24*time.Hour {
            return loc
        }
    }
    
    // Fetch from API with more fields
    url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,region,regionName,city,lat,lon,isp,org,as", ip)
    resp, err := http.Get(url)
    if err != nil {
        return nil
    }
    defer resp.Body.Close()
    
    var result struct {
        Status string `json:"status"`
        *GeoLocation
    }
    
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil
    }
    
    if result.Status != "success" {
        return nil
    }
    
    result.GeoLocation.LastUpdate = time.Now()
    ui.geoCache[ip] = result.GeoLocation
    
    return result.GeoLocation
}

// clearGeoCache clears the geo location cache
func (ui *UI) clearGeoCache() {
    ui.geoCache = make(map[string]*GeoLocation)
}

// showPluginsPage displays the plugins view
func (ui *UI) showPluginsPage() {
    ui.updatePluginView()
    
    ui.pluginView.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
        switch event.Key() {
        case tcell.KeyEscape:
            ui.pages.SwitchToPage("main")
            return nil
        case tcell.KeyUp:
            if ui.selectedPlugin > 0 {
                ui.selectedPlugin--
                ui.updatePluginView()
            }
            return nil
        case tcell.KeyDown:
            if ui.selectedPlugin < len(ui.plugins)-1 {
                ui.selectedPlugin++
                ui.updatePluginView()
            }
            return nil
        }
        return event
    })
    
    ui.pages.AddPage("plugins", ui.pluginView, true, true)
    ui.app.SetFocus(ui.pluginView)
}

// updatePluginView refreshes the plugin display
func (ui *UI) updatePluginView() {
    ui.pluginView.Clear()
    
    if len(ui.plugins) == 0 {
        fmt.Fprintf(ui.pluginView, "[%s]No plugins loaded.[white]\n\n", 
            graph.ColorToHex(ui.theme.WarningColor))
        fmt.Fprintf(ui.pluginView, "Use --plugins flag to load plugins.\n")
        return
    }
    
    // Header
    fmt.Fprintf(ui.pluginView, "[%s]═══ Loaded Plugins ═══[white]\n\n", 
        graph.ColorToHex(ui.theme.PrimaryColor))
    
    // Display each plugin
    for i, plugin := range ui.plugins {
        // Plugin name and status
        statusColor := ui.theme.SuccessColor
        if plugin.Status != "Active" {
            statusColor = ui.theme.WarningColor
        }
        
        marker := " "
        if i == ui.selectedPlugin {
            marker = "►"
        }
        
        fmt.Fprintf(ui.pluginView, "%s [%s]%s[white] - [%s]%s[white]\n", 
            marker,
            graph.ColorToHex(ui.theme.PrimaryColor), 
            plugin.Name,
            graph.ColorToHex(statusColor),
            plugin.Status)
        
        // Plugin description
        if plugin.Description != "" {
            fmt.Fprintf(ui.pluginView, "  %s\n", plugin.Description)
        }
        
        // Last update
        fmt.Fprintf(ui.pluginView, "  Last Update: %s ago\n", 
            time.Since(plugin.LastUpdate).Round(time.Second))
        
        // Show recent output for selected plugin
        if i == ui.selectedPlugin && len(plugin.Output) > 0 {
            fmt.Fprintf(ui.pluginView, "\n  [%s]Recent Output:[white]\n", 
                graph.ColorToHex(ui.theme.SecondaryColor))
            
            // Show last 10 lines of output
            start := 0
            if len(plugin.Output) > 10 {
                start = len(plugin.Output) - 10
            }
            
            for _, line := range plugin.Output[start:] {
                fmt.Fprintf(ui.pluginView, "  │ %s\n", line)
            }
        }
        
        fmt.Fprintln(ui.pluginView)
    }
    
    // Footer
    fmt.Fprintf(ui.pluginView, "\n[%s]Press ↑/↓ to navigate, ESC to return[white]", 
        graph.ColorToHex(ui.theme.BorderColor))
}

// populateInterfaceList loads available interfaces
func (ui *UI) populateInterfaceList() {
    ui.interfaceList.Clear()
    ifaces, err := netcap.GetInterfaces()
    if err != nil {
        ui.showError(fmt.Sprintf("Error getting interfaces: %v", err))
        return
    }
    for i, iface := range ifaces {
        desc := iface.Description
        if desc == "" {
            desc = "No description"
        }
        ui.interfaceList.AddItem(iface.Name, desc, rune('a'+i), nil)
    }
    if ui.selectedIface == "" && ui.interfaceList.GetItemCount() > 0 {
        ui.selectedIface, _ = ui.interfaceList.GetItemText(0)
        ui.interfaceList.SetCurrentItem(0)
    }
}

// updateStatsView refreshes the stats panel
func (ui *UI) updateStatsView() {
    if ui.selectedIface == "" {
        return
    }
    stats := ui.networkMonitor.GetInterfaceStats()
    ifStats, ok := stats[ui.selectedIface]
    if !ok {
        ui.statsView.SetText("[yellow]" + i18n.T("no_statistics_available"))
        return
    }
    // compute current in/out rates
    inRate, outRate := ui.getNetworkRates()
    text := fmt.Sprintf(
        "[green]" + i18n.T("interface") + ":[white] %s\n\n"+
        "[green]" + i18n.T("in") + ":[white] %s (%d pkts)\n"+
        "[green]" + i18n.T("out") + ":[white] %s (%d pkts)\n"+
        "[green]" + i18n.T("in_rate") + ":[white] %s/s\n"+
        "[green]" + i18n.T("out_rate") + ":[white] %s/s\n\n"+
        "[green]" + i18n.T("connections") + ":[white] %d\n",
        ui.selectedIface,
        utils.FormatBytes(ifStats.BytesIn), ifStats.PacketsIn,
        utils.FormatBytes(ifStats.BytesOut), ifStats.PacketsOut,
        utils.FormatBytes(uint64(inRate)), utils.FormatBytes(uint64(outRate)),
        len(ifStats.Connections),
    )
    ui.statsView.SetText(text)
}

// updateConnectionTable refreshes the connections table
func (ui *UI) updateConnectionTable() {
    selRow, _ := ui.connectionTable.GetSelection()
    var selConn *netcap.Connection
    if selRow > 0 && selRow-1 < len(ui.connections) {
        selConn = ui.connections[selRow-1]
    }
    ui.connectionTable.Clear()
    headers := []string{i18n.T("source"), i18n.T("destination"), i18n.T("proto"), i18n.T("svc"), i18n.T("bytes"), i18n.T("pkts"), i18n.T("activity"), i18n.T("last_seen")}
    for i, h := range headers {
        ui.connectionTable.SetCell(0, i, tview.NewTableCell(h).
            SetTextColor(ui.theme.TitleColor).
            SetSelectable(false).
            SetExpansion(1))
    }
    if ui.selectedIface == "" {
        return
    }
    ui.connections = ui.networkMonitor.GetConnections(ui.selectedIface)
    sort.Slice(ui.connections, func(i, j int) bool {
        a, b := ui.connections[i], ui.connections[j]
        switch ui.sortBy {
        case "bytes":
            return a.Size > b.Size
        case "packets":
            return a.Packets > b.Packets
        case "time":
            return a.LastSeen.After(b.LastSeen)
        }
        return false
    })
    for i, c := range ui.connections {
        row := i + 1
        
        // Check if connection is marked
        connKey := getConnectionKey(c)
        marked := ui.markedConnections[connKey]
        markPrefix := ""
        if marked {
            markPrefix = "[X] "
        }
        
        ui.connectionTable.SetCell(row, 0, tview.NewTableCell(markPrefix + c.SrcIP.String()).SetTextColor(ui.theme.PrimaryColor).SetExpansion(1))
        ui.connectionTable.SetCell(row, 1, tview.NewTableCell(c.DstIP.String()).SetTextColor(ui.theme.PrimaryColor).SetExpansion(1))
        // protocol color
        protoColor := ui.theme.SecondaryColor
        switch c.Protocol {
        case "TCP": protoColor = tcell.ColorGreen
        case "UDP": protoColor = tcell.ColorBlue
        case "ICMP": protoColor = tcell.ColorFuchsia
        }
        ui.connectionTable.SetCell(row, 2, tview.NewTableCell(c.Protocol).SetTextColor(protoColor).SetExpansion(1))
        ui.connectionTable.SetCell(row, 3, tview.NewTableCell(c.Service).SetTextColor(ui.theme.TitleColor).SetExpansion(1))
        ui.connectionTable.SetCell(row, 4, tview.NewTableCell(fmt.Sprintf("%d", c.Size)).SetTextColor(ui.theme.SecondaryColor).SetExpansion(1))
        ui.connectionTable.SetCell(row, 5, tview.NewTableCell(fmt.Sprintf("%d", c.Packets)).SetTextColor(ui.theme.PrimaryColor).SetExpansion(1))
        
        // Generate sparkline for connection activity
        sparkline := ui.getConnectionSparkline(connKey)
        ui.connectionTable.SetCell(row, 6, tview.NewTableCell(sparkline).SetTextColor(ui.theme.PrimaryColor))
        
        ui.connectionTable.SetCell(row, 7, tview.NewTableCell(c.LastSeen.Format(time.Kitchen)).SetTextColor(ui.theme.TitleColor).SetExpansion(1))
    }
    newRow := 0
    if selConn != nil {
        for i, c := range ui.connections {
            if c == selConn {
                newRow = i + 1
                break
            }
        }
    }
    if newRow == 0 {
        if selRow > 0 && selRow <= len(ui.connections) {
            newRow = selRow
        } else if len(ui.connections) > 0 {
            newRow = 1
        }
    }
    ui.connectionTable.Select(newRow, 0)
    if newRow > 0 && newRow-1 < len(ui.connections) {
        ui.showConnectionDetails(ui.connections[newRow-1])
    } else {
        ui.detailView.SetText("")
    }
}

// showConnectionDetails shows detailed info for a connection
func (ui *UI) showConnectionDetails(c *netcap.Connection) {
    if c == nil {
        ui.detailView.SetText("")
        return
    }
    text := fmt.Sprintf(
        "[green]" + i18n.T("src") + ":[white] %s:%d\n"+
        "[green]" + i18n.T("dst") + ":[white] %s:%d\n"+
        "[green]" + i18n.T("proto") + ":[white] %s\n"+
        "[green]" + i18n.T("svc") + ":[white] %s\n"+
        "[green]" + i18n.T("bytes") + ":[white] %s\n"+
        "[green]" + i18n.T("pkts") + ":[white] %d\n",
        c.SrcIP, c.SrcPort, c.DstIP, c.DstPort,
        c.Protocol, c.Service,
        utils.FormatBytes(c.Size), c.Packets,
    )
    // Don't show hex dump in the detail view to avoid performance issues
    ui.detailView.SetText(text)
}

// showError displays an error modal
func (ui *UI) showError(msg string) {
    modal := tview.NewModal().SetText(msg).
        AddButtons([]string{i18n.T("ok")}).
        SetDoneFunc(func(_ int, _ string) { ui.pages.SwitchToPage("main") })
    ui.pages.AddPage("error", modal, true, true)
}

// startUpdateLoop starts periodic UI updates
func (ui *UI) startUpdateLoop() {
    lastInterval := ui.updateInterval
    ticker := time.NewTicker(ui.updateInterval)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            if !ui.paused {
                ui.app.QueueUpdateDraw(ui.updateData)
            }
            ui.app.QueueUpdateDraw(ui.updateStatusBar)
            // Reset ticker if interval changed
            if lastInterval != ui.updateInterval {
                ticker.Stop()
                ticker = time.NewTicker(ui.updateInterval)
                lastInterval = ui.updateInterval
            }
        case <-ui.stopChan:
            return
        }
    }
}

// updateStatusBar updates the status bar with current state
func (ui *UI) updateStatusBar() {
    var pauseText string
    if ui.paused {
        pauseText = " [PAUSED]"
    }
    
    var recordText string
    if ui.recording {
        recordText = fmt.Sprintf(" [REC %s]", time.Since(ui.recordingStart).Round(time.Second))
    }
    
    updateText := fmt.Sprintf("%.1fs", ui.updateInterval.Seconds())
    layoutText := ui.layoutPresets[ui.currentLayout]
    
    status := fmt.Sprintf("Layout: %s | Update: %s%s%s | q:Exit h:Help p:Preset +/-:Speed Space:Pause R:Record L:Load", 
        layoutText, updateText, pauseText, recordText)
    
    if ui.filterString != "" {
        status += fmt.Sprintf(" | Filter: %s", ui.filterString)
    }
    
    ui.statusBar.SetText(status).SetTextColor(ui.theme.StatusBarTextColor)
}

// getNetworkRates computes in/outbps
func (ui *UI) getNetworkRates() (float64, float64) {
    if ui.selectedIface == "" { return 0, 0 }
    stats := ui.networkMonitor.GetInterfaceStats()
    if s, ok := stats[ui.selectedIface]; ok {
        now := time.Now()
        elapsed := now.Sub(ui.lastUpdateTime)
        if ui.lastUpdateTime.IsZero() || elapsed < 100*time.Millisecond {
            ui.lastBytesIn, ui.lastBytesOut = s.BytesIn, s.BytesOut
            ui.lastUpdateTime = now
            return 0, 0
        }
        inRate := float64(s.BytesIn - ui.lastBytesIn) / elapsed.Seconds()
        outRate := float64(s.BytesOut - ui.lastBytesOut) / elapsed.Seconds()
        ui.lastBytesIn, ui.lastBytesOut, ui.lastUpdateTime = s.BytesIn, s.BytesOut, now
        return inRate, outRate
    }
    return 0, 0
}

// updateProtocolView updates the protocol usage text view
func (ui *UI) updateProtocolView() {
    buf := ui.networkMonitor.GetPacketBuffer()
    counts := make(map[string]int)
    for _, p := range buf { counts[p.Service]++ }
    total := len(buf)
    // sort services for consistent ordering
    keys := make([]string, 0, len(counts))
    for k := range counts { keys = append(keys, k) }
    sort.Strings(keys)
    // color-coded lines
    lines := []string{}
    for i, svc := range keys {
        v := counts[svc]
        perc := 0
        if total > 0 { perc = v * 100 / total }
        color := pieColors[i%len(pieColors)]
        lines = append(lines, fmt.Sprintf("%s%s %d%%", color, svc, perc))
    }
    ui.protocolView.SetText(strings.Join(lines, "\n"))
}

// showHelpPage displays the help screen
func (ui *UI) showHelpPage() {
    ui.pages.RemovePage("help")
    
    // Get current context
    currentPage, _ := ui.pages.GetFrontPage()
    focusedPrimitive := ui.app.GetFocus()
    
    // Build context-sensitive help
    helpText := ui.buildContextualHelp(currentPage, focusedPrimitive)
    
    ui.helpView.SetText(helpText)
    ui.helpView.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
        if event.Key() == tcell.KeyEscape || event.Rune() == '?' || event.Rune() == 'h' {
            ui.pages.SwitchToPage("main")
            return nil
        }
        return event
    })
    ui.pages.AddPage("help", ui.helpView, true, true)
    ui.app.SetFocus(ui.helpView)
}

// buildContextualHelp generates help text based on current context
func (ui *UI) buildContextualHelp(currentPage string, focused tview.Primitive) string {
    var help strings.Builder
    
    // Header
    help.WriteString(fmt.Sprintf("[%s]NetMon Help - Press ESC or ? to close[white]\n\n", 
        graph.ColorToHex(ui.theme.TitleColor)))
    
    // Global shortcuts
    help.WriteString(fmt.Sprintf("[%s]═══ Global Shortcuts ═══[white]\n", 
        graph.ColorToHex(ui.theme.PrimaryColor)))
    help.WriteString(`
  q       - Exit menu (Options/Help/Quit)
  h/?     - Show this help
  o       - Options/settings menu
  p       - Cycle layout presets
  +/-     - Increase/decrease update speed
  Space   - Pause/resume updates
  Tab     - Switch focus between panels
  
`)
    
    // Navigation
    help.WriteString(fmt.Sprintf("[%s]═══ Navigation ═══[white]\n", 
        graph.ColorToHex(ui.theme.PrimaryColor)))
    help.WriteString(`
  n/N     - Next/previous interface
  ↑/↓     - Navigate lists and tables
  Enter   - Select/view details
  ESC     - Back to main view
  
`)
    
    // Panel visibility
    help.WriteString(fmt.Sprintf("[%s]═══ Panel Toggles ═══[white]\n", 
        graph.ColorToHex(ui.theme.PrimaryColor)))
    help.WriteString(`
  0       - Toggle interfaces panel
  1       - Toggle statistics panel
  2       - Toggle traffic graphs
  3       - Toggle protocol view
  4-6     - Toggle pie charts
  7       - Toggle connections table
  8       - Toggle connection details
  
`)
    
    // Context-specific help
    switch {
    case focused == ui.connectionTable:
        help.WriteString(fmt.Sprintf("[%s]═══ Connection Table ═══[white]\n", 
            graph.ColorToHex(ui.theme.SecondaryColor)))
        help.WriteString(`
  Enter   - View connection packets
  k/Del   - Kill connection
  e       - Export connection data
  x       - Mark/unmark connection
  a       - Select all connections
  s       - Sort connections
  f       - Filter connections
  
  Mouse:
  - Click to select
  - Right-click for context menu
  - Double-click to view packets
`)
        
    case focused == ui.interfaceList:
        help.WriteString(fmt.Sprintf("[%s]═══ Interface List ═══[white]\n", 
            graph.ColorToHex(ui.theme.SecondaryColor)))
        help.WriteString(`
  ↑/↓     - Select interface
  Enter   - Apply selection
  r       - Refresh interface list
  
  Mouse:
  - Click to select
  - Scroll to navigate
`)
        
    case currentPage == "main" && focused == ui.trafficGraph:
        help.WriteString(fmt.Sprintf("[%s]═══ Traffic Graphs ═══[white]\n", 
            graph.ColorToHex(ui.theme.SecondaryColor)))
        help.WriteString(`
  t       - Toggle graph style (Braille/Block/TTY)
  
  Mouse:
  - Click title to cycle graph styles
`)
        
    case currentPage == "geo":
        help.WriteString(fmt.Sprintf("[%s]═══ Geographic View ═══[white]\n", 
            graph.ColorToHex(ui.theme.SecondaryColor)))
        help.WriteString(`
  Tab     - Toggle focus between map and table
  r       - Refresh geo data (clear cache)
  ↑/↓     - Navigate table rows
  
  The world map shows connection density with:
  █ ▓ ▒ ░ symbols for traffic volume
  Colors indicate percentage of max connections
`)
    }
    
    // Features and filters
    help.WriteString(fmt.Sprintf("\n[%s]═══ Features & Filters ═══[white]\n", 
        graph.ColorToHex(ui.theme.PrimaryColor)))
    help.WriteString(`
  b       - Set BPF (Berkeley Packet Filter)
  c       - Clear all filters
  d       - Dashboard menu
  e       - Export data menu
  u       - UI profiles (save/load)
  i       - Interface statistics page
  g       - Geographic IP mapping
  G       - Show plugins view
  &       - Border styles preview
  r       - Force refresh
  
`)
    
    // Current status
    help.WriteString(fmt.Sprintf("[%s]═══ Current Status ═══[white]\n", 
        graph.ColorToHex(ui.theme.TitleColor)))
    help.WriteString(fmt.Sprintf(`
  Layout:         %s
  Update Speed:   %.1fs
  Graph Style:    %s
  Theme:          %s
  Paused:         %v
`,
        ui.layoutPresets[ui.currentLayout],
        ui.updateInterval.Seconds(),
        []string{"Braille", "Block", "TTY"}[ui.graphStyle],
        ui.getCurrentThemeName(),
        ui.paused))
    
    return help.String()
}

// getCurrentThemeName returns the name of the current theme
func (ui *UI) getCurrentThemeName() string {
    for name, theme := range Themes {
        if theme == ui.theme {
            return name
        }
    }
    return "Custom"
}

// showBorderStylesPreview shows a preview of all border styles
func (ui *UI) showBorderStylesPreview() {
	// Create a text view to show border style examples
	preview := tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(false)
	
	preview.SetBorder(true).
		SetTitle("Border Styles Preview").
		SetTitleColor(ui.theme.TitleColor).
		SetBorderColor(ui.theme.BorderColor)
	
	// Generate preview text
	var text string
	text += fmt.Sprintf("[%s]═══ Border Styles Preview ═══[white]\n\n", 
		graph.ColorToHex(ui.theme.PrimaryColor))
	
	// Sort border style names for consistent display
	styleNames := BorderStyleNames()
	for _, styleName := range styleNames {
		style := GetBorderStyle(styleName)
		text += fmt.Sprintf("[%s]%s Style:[white]\n", 
			graph.ColorToHex(ui.theme.SecondaryColor), styleName)
		
		// Draw a sample box
		text += fmt.Sprintf("  %c%c%c%c%c%c%c\n", 
			style.TopLeft, style.Horizontal, style.HorizontalDown, 
			style.Horizontal, style.Horizontal, style.Horizontal, style.TopRight)
		text += fmt.Sprintf("  %c     %c\n", style.Vertical, style.Vertical)
		text += fmt.Sprintf("  %c%c%c%c%c%c%c\n", 
			style.VerticalRight, style.Horizontal, style.Cross, 
			style.Horizontal, style.Horizontal, style.Horizontal, style.VerticalLeft)
		text += fmt.Sprintf("  %c     %c\n", style.Vertical, style.Vertical)
		text += fmt.Sprintf("  %c%c%c%c%c%c%c\n\n", 
			style.BottomLeft, style.Horizontal, style.HorizontalUp, 
			style.Horizontal, style.Horizontal, style.Horizontal, style.BottomRight)
	}
	
	text += fmt.Sprintf("\n[%s]Current style:[white] %s\n", 
		graph.ColorToHex(ui.theme.PrimaryColor), ui.borderStyle)
	text += fmt.Sprintf("\n[%s]Press ESC to return[white]", 
		graph.ColorToHex(ui.theme.BorderColor))
	
	preview.SetText(text)
	
	// Handle escape key
	preview.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			ui.pages.SwitchToPage("main")
			return nil
		}
		return event
	})
	
	ui.pages.AddPage("borderPreview", preview, true, true)
	ui.app.SetFocus(preview)
}

// SetTheme applies a named theme to UI components
func (ui *UI) SetTheme(name string) *UI {
    t, ok := Themes[name]
    if !ok {
        t = Themes["Dark+"]
    }
    ui.theme = t
    ui.interfaceList.SetBorderColor(t.BorderColor).SetTitleColor(t.TitleColor)
    ui.statsView.SetBorderColor(t.BorderColor).SetTitleColor(t.TitleColor)
    ui.trafficGraph.SetBorderColor(t.BorderColor).SetTitleColor(t.TitleColor)
    ui.networkGraph.SetColor(t.PrimaryColor).SetSecondaryColor(t.SecondaryColor)
    ui.protocolView.SetBorderColor(t.BorderColor).SetTitleColor(t.TitleColor)
    ui.connectionTable.SetBorderColor(t.BorderColor).SetTitleColor(t.TitleColor)
    ui.detailView.SetBorderColor(t.BorderColor).SetTitleColor(t.TitleColor)
    ui.servicePieView.SetBorderColor(t.PieBorderColor).SetTitleColor(t.PieTitleColor)
    ui.protocolPieView.SetBorderColor(t.PieBorderColor).SetTitleColor(t.PieTitleColor)
    ui.securePieView.SetBorderColor(t.PieBorderColor).SetTitleColor(t.PieTitleColor)
    ui.ifaceStatsView.SetBorderColor(t.BorderColor).SetTitleColor(t.TitleColor)
    ui.histView.SetBorderColor(t.BorderColor).SetTitleColor(t.TitleColor)
    ui.dnsHttpView.SetBorderColor(t.BorderColor).SetTitleColor(t.TitleColor)
    ui.geoView.SetBorderColor(t.BorderColor).SetTitleColor(t.TitleColor)
    ui.geoMapView.SetBorderColor(t.BorderColor).SetTitleColor(t.TitleColor)
    ui.helpView.SetBorderColor(t.BorderColor).SetTitleColor(t.TitleColor)
    ui.rawView.SetBorderColor(t.BorderColor).SetTitleColor(t.TitleColor)
    ui.statusBar.SetBackgroundColor(t.StatusBarBgColor)
    ui.statusBar.SetTextColor(t.StatusBarTextColor)

    // Update pie chart segment colors to match theme
    pieColors = []string{
        "[" + graph.ColorToHex(t.PrimaryColor) + "]",
        "[" + graph.ColorToHex(t.SecondaryColor) + "]",
        "[" + graph.ColorToHex(t.PieTitleColor) + "]",
        "[" + graph.ColorToHex(t.TitleColor) + "]",
    }

    return ui
}

// SetStyle applies a named UI style (Standard or btop).
func (ui *UI) SetStyle(name string) *UI {
    def, ok := Styles[name]
    if ok {
        ui.styleName = name
    } else {
        def = Styles["Standard"]
        ui.styleName = "Standard"
    }
    // Override border runes for the selected style
    tview.Borders.TopLeft = def.BorderTL
    tview.Borders.TopRight = def.BorderTR
    tview.Borders.BottomLeft = def.BorderBL
    tview.Borders.BottomRight = def.BorderBR
    tview.Borders.Horizontal = def.BorderH
    tview.Borders.Vertical = def.BorderV
    return ui
}

// SetGradientEnabled toggles static gradient shading on the traffic and network graphs
func (ui *UI) SetGradientEnabled(enabled bool) *UI {
    ui.trafficGraph.SetGradientEnabled(enabled)
    ui.networkGraph.SetGradientEnabled(enabled)
    return ui
}

// Run starts the UI application
func (ui *UI) Run() error {
    ui.bpfString = ui.networkMonitor.GetFilterExpression()
    ui.populateInterfaceList()
    ui.networkGraph.Start()
    go ui.startUpdateLoop()
    ui.updateData()
    
    // Handle startup modes
    if ui.startupVizID != "" {
        // Start with specific visualization
        ui.app.SetAfterDrawFunc(func(screen tcell.Screen) {
            ui.app.SetAfterDrawFunc(nil) // Only run once
            ui.showVisualizationFullscreen(ui.startupVizID)
        })
    } else if ui.startupDashboard != "" {
        // Start with specific dashboard
        ui.app.SetAfterDrawFunc(func(screen tcell.Screen) {
            ui.app.SetAfterDrawFunc(nil) // Only run once
            dm := NewDashboardManager()
            if layout, exists := dm.GetDashboard(ui.startupDashboard); exists {
                ui.showDashboard(layout)
            } else {
                ui.showError(fmt.Sprintf("Dashboard '%s' not found", ui.startupDashboard))
            }
        })
    }
    
    return ui.app.Run()
}

// Stop cleans up resources and exits
func (ui *UI) Stop() {
    close(ui.stopChan)
    ui.networkGraph.Stop()
    ui.networkMonitor.StopAllCaptures()
    ui.app.Stop()
}

// showRawPacketPage displays hex dump of a packet
func (ui *UI) showRawPacketPage(idx int) {
    ui.pages.RemovePage("raw")
    packets := ui.networkMonitor.GetPacketBuffer()
    if idx < 0 || idx >= len(packets) {
        return
    }
    var sb strings.Builder
    resetTag := colorTag(ui.theme.TitleColor)
    data := packets[idx].Data
    dumpTag := colorTag(ui.theme.PrimaryColor)
    // Packet Layers ASCII tree
    pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
    sb.WriteString(i18n.T("packet_layers") + ":\n")
    ly := pkt.Layers()
    for i, layer := range ly {
        prefix := "├─ "
        if i == len(ly)-1 { prefix = "└─ " }
        sb.WriteString(prefix + layer.LayerType().String() + "\n")
    }
    sb.WriteString("\n")
    sb.WriteString(fmt.Sprintf("[%s]" + i18n.T("hex_dump") + ":[%s]\n", dumpTag, resetTag))
    for i := 0; i < len(data); i += 16 {
        sb.WriteString(fmt.Sprintf("[%s]%04x  [%s]", colorTag(ui.theme.SecondaryColor), i, resetTag))
        for j := 0; j < 16; j++ {
            if i+j < len(data) {
                b := data[i+j]
                var col tcell.Color
                switch {
                case b < 64:
                    col = tcell.ColorDarkGray
                case b < 128:
                    col = tcell.ColorGray
                case b < 192:
                    col = tcell.ColorLightGray
                default:
                    col = ui.theme.PrimaryColor
                }
                sb.WriteString(fmt.Sprintf("[%s]%02x[%s] ", colorTag(col), b, resetTag))
            } else {
                sb.WriteString("   ")
            }
        }
        sb.WriteString(" ")
        for j := 0; j < 16; j++ {
            if i+j < len(data) {
                b := data[i+j]
                if b >= 32 && b < 127 {
                    sb.WriteString(fmt.Sprintf("[%s]%c[%s]", colorTag(ui.theme.SecondaryColor), b, resetTag))
                } else {
                    sb.WriteString(fmt.Sprintf("[%s].[%s]", colorTag(ui.theme.SecondaryColor), resetTag))
                }
            }
        }
        sb.WriteString("\n")
    }
    dump := sb.String()
    ui.rawView.SetText(dump)
    ui.rawDumpLines = strings.Split(dump, "\n")
    ui.rawView.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
        if event.Key() == tcell.KeyEscape {
            ui.pages.SwitchToPage("packets")
            return nil
        }
        // Search in hex dump
        if event.Rune() == '/' {
            // create search input field
            inputField := tview.NewInputField().SetLabel(i18n.T("search") + ": ")
            inputField.SetDoneFunc(func(key tcell.Key) {
                if key == tcell.KeyEnter {
                    term := inputField.GetText()
                    matched := []string{}
                    for _, line := range ui.rawDumpLines {
                        if strings.Contains(strings.ToLower(line), strings.ToLower(term)) {
                            matched = append(matched, line)
                        }
                    }
                    ui.rawView.SetText(strings.Join(matched, "\n"))
                    ui.pages.RemovePage("search")
                    ui.app.SetFocus(ui.rawView)
                }
            })
            ui.pages.AddPage("search", inputField, true, true)
            ui.app.SetFocus(inputField)
            return nil
        }
        return event
    })
    ui.pages.AddPage("raw", ui.rawView, true, true)
    ui.app.SetFocus(ui.rawView)
}

// showConnectionPacketsPage displays packets for the selected connection
func (ui *UI) showConnectionPacketsPage() {
    ui.pages.RemovePage("connPackets")
    conn := ui.selectedConnection
    if conn == nil {
        return
    }
    packets := ui.networkMonitor.GetPacketBuffer()
    table := tview.NewTable().SetBorders(false)
    table.SetSelectable(true, false).SetFixed(1, 0)
    title := fmt.Sprintf(i18n.T("packets_for") + " %s:%d ↔ %s:%d", conn.SrcIP, conn.SrcPort, conn.DstIP, conn.DstPort)
    table.SetBorder(true).SetTitle(title)
    headers := []string{i18n.T("time"), i18n.T("source"), i18n.T("dest"), i18n.T("proto"), i18n.T("service"), i18n.T("len")}
    for i, h := range headers {
        table.SetCell(0, i, tview.NewTableCell(h).
            SetTextColor(tcell.ColorYellow).
            SetSelectable(false))
    }
    row := 1
    for _, p := range packets {
        if (p.SrcIP.String() == conn.SrcIP.String() && p.SrcPort == conn.SrcPort && p.DstIP.String() == conn.DstIP.String() && p.DstPort == conn.DstPort && p.Protocol == conn.Protocol) ||
           (p.SrcIP.String() == conn.DstIP.String() && p.SrcPort == conn.DstPort && p.DstIP.String() == conn.SrcIP.String() && p.DstPort == conn.SrcPort && p.Protocol == conn.Protocol) {
            table.SetCell(row, 0, tview.NewTableCell(p.Timestamp.Format("15:04:05")))
            table.SetCell(row, 1, tview.NewTableCell(fmt.Sprintf("%s:%d", p.SrcIP, p.SrcPort)))
            table.SetCell(row, 2, tview.NewTableCell(fmt.Sprintf("%s:%d", p.DstIP, p.DstPort)))
            // protocol color
            protoColor := ui.theme.SecondaryColor
            switch p.Protocol {
            case "TCP": protoColor = tcell.ColorGreen
            case "UDP": protoColor = tcell.ColorBlue
            case "ICMP": protoColor = tcell.ColorFuchsia
            }
            table.SetCell(row, 3, tview.NewTableCell(p.Protocol).SetTextColor(protoColor))
            table.SetCell(row, 4, tview.NewTableCell(p.Service))
            table.SetCell(row, 5, tview.NewTableCell(fmt.Sprintf("%d", p.Length)))
            row++
        }
    }
    table.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
        switch event.Key() {
        case tcell.KeyEscape:
            ui.pages.SwitchToPage("main")
            return nil
        case tcell.KeyEnter:
            r, _ := table.GetSelection()
            if r > 0 {
                ui.showRawPacketPage(r - 1)
            }
            return nil
        }
        return event
    })
    ui.pages.AddPage("connPackets", table, true, true)
    ui.app.SetFocus(table)
}

// getCPUMemory returns current CPU and memory usage percentages
func (ui *UI) getCPUMemory() (float64, float64) {
    cpuPercents, err := cpu.Percent(0, false)
    var cpuPct float64
    if err == nil && len(cpuPercents) > 0 {
        cpuPct = cpuPercents[0]
    }
    vm, err := mem.VirtualMemory()
    var memPct float64
    if err == nil {
        memPct = vm.UsedPercent
    }
    return cpuPct, memPct
}

// colorTag returns a hex code suitable for tview dynamic color tags.
func colorTag(c tcell.Color) string {
    rgb := uint32(c)
    r := (rgb >> 16) & 0xff
    g := (rgb >> 8) & 0xff
    b := rgb & 0xff
    return fmt.Sprintf("#%02x%02x%02x", r, g, b)
}

// showExitMenu displays a btop-style exit menu
func (ui *UI) showExitMenu() {
	modal := tview.NewModal().
		SetText(i18n.T("exit_menu_text")).
		AddButtons([]string{i18n.T("options"), i18n.T("help"), i18n.T("quit"), i18n.T("cancel")}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			switch buttonIndex {
			case 0: // Options
				ui.pages.RemovePage("exit")
				ui.showOptionsMenu()
			case 1: // Help
				ui.pages.RemovePage("exit")
				ui.showHelpPage()
			case 2: // Quit
				ui.Stop()
			case 3: // Cancel
				ui.pages.RemovePage("exit")
			}
		})
	ui.pages.AddPage("exit", modal, true, true)
}

// showOptionsMenu displays the options/settings menu
func (ui *UI) showOptionsMenu() {
	// Create a basic form to test
	form := tview.NewForm()
	
	// Theme selection
	themeNames := make([]string, 0, len(Themes))
	currentThemeIndex := 0
	for name := range Themes {
		themeNames = append(themeNames, name)
	}
	sort.Strings(themeNames)
	
	// Find current theme index
	currentThemeName := ui.getCurrentThemeName()
	for i, name := range themeNames {
		if name == currentThemeName {
			currentThemeIndex = i
			break
		}
	}
	
	// Update interval options
	intervals := []string{"0.5s", "1s", "2s", "5s", "10s"}
	currentIntervalIndex := 1 // default to 1s
	for i, interval := range intervals {
		if interval == fmt.Sprintf("%.1fs", ui.updateInterval.Seconds()) {
			currentIntervalIndex = i
			break
		}
	}
	
	// Graph style options
	graphStyles := []string{"Braille", "Block", "TTY"}
	currentStyleIndex := int(ui.graphStyle)
	
	// Store temporary values for checkboxes
	var tempGradientEnabled = true
	var tempShowLegend = true
	
	// Border style options
	borderStyles := BorderStyleNames()
	currentBorderIndex := 0
	for i, style := range borderStyles {
		if style == ui.borderStyle {
			currentBorderIndex = i
			break
		}
	}
	
	form.
		AddDropDown("Theme", themeNames, currentThemeIndex, func(option string, index int) {
			ui.theme = Themes[option]
			ui.theme.calculateGradients()
			ui.applyTheme()
		}).
		AddDropDown("Update Interval", intervals, currentIntervalIndex, func(option string, index int) {
			duration, _ := time.ParseDuration(option)
			ui.updateInterval = duration
			ui.updateStatusBar()
		}).
		AddDropDown("Graph Style", graphStyles, currentStyleIndex, func(option string, index int) {
			ui.graphStyle = graph.GraphStyle(index)
		}).
		AddDropDown("Border Style", borderStyles, currentBorderIndex, func(option string, index int) {
			ui.borderStyle = option
			// Will be applied when the grid is rebuilt
		}).
		AddDropDown("Border Animation", AnimationNames, 0, func(option string, index int) {
			ui.borderAnimation = option
			ui.updateAnimationTicker()
		}).
		AddCheckbox("Enable Gradients", tempGradientEnabled, func(checked bool) {
			tempGradientEnabled = checked
		}).
		AddCheckbox("Show Legend", tempShowLegend, func(checked bool) {
			tempShowLegend = checked
		}).
		AddButton("Apply", func() {
			// Apply all settings when Apply is clicked
			if ui.trafficGraph != nil {
				for _, gw := range ui.trafficGraph.GraphWidgets() {
					if gw != nil {
						gw.SetStyle(ui.graphStyle)
						gw.SetGradientEnabled(tempGradientEnabled)
						gw.ShowLegend(tempShowLegend)
					}
				}
			}
			// Rebuild layout to apply new border style
			ui.rebuildLayout()
			ui.pages.RemovePage("options")
		}).
		AddButton("Cancel", func() {
			ui.pages.RemovePage("options")
		})
	
	form.SetBorder(true).SetTitle("Options").SetTitleAlign(tview.AlignCenter)
	form.SetButtonsAlign(tview.AlignCenter)
	
	// Handle escape key
	form.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			ui.pages.RemovePage("options")
			return nil
		}
		return event
	})
	
	// Create a flex container to center the form
	flex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().
			AddItem(nil, 0, 1, false).
			AddItem(form, 60, 0, true).
			AddItem(nil, 0, 1, false), 20, 0, true).
		AddItem(nil, 0, 1, false)
	
	ui.pages.AddPage("options", flex, true, true)
}

// applyTheme applies the current theme to all UI components
func (ui *UI) applyTheme() {
	// Update all component colors
	ui.interfaceList.SetBorderColor(ui.theme.BorderColor).SetTitleColor(ui.theme.TitleColor)
	ui.statsView.SetBorderColor(ui.theme.BorderColor).SetTitleColor(ui.theme.TitleColor)
	ui.trafficGraph.SetBorderColor(ui.theme.BorderColor).SetTitleColor(ui.theme.TitleColor)
	ui.protocolView.SetBorderColor(ui.theme.BorderColor).SetTitleColor(ui.theme.TitleColor)
	ui.connectionTable.SetBorderColor(ui.theme.BorderColor).SetTitleColor(ui.theme.TitleColor)
	ui.detailView.SetBorderColor(ui.theme.BorderColor).SetTitleColor(ui.theme.TitleColor)
	ui.statusBar.SetBackgroundColor(ui.theme.StatusBarBgColor)
	
	// Update graph colors
	if ui.trafficGraph != nil {
		for _, gw := range ui.trafficGraph.GraphWidgets() {
			if gw != nil {
				gw.SetColor(ui.theme.PrimaryColor)
				gw.SetSecondaryColor(ui.theme.SecondaryColor)
			}
		}
	}
	
	// Don't call Draw() here as it may cause deadlock
	// The display will refresh on the next update cycle
}

// cycleLayoutPreset cycles through available layout presets
func (ui *UI) cycleLayoutPreset() {
	ui.currentLayout = (ui.currentLayout + 1) % len(ui.layoutPresets)
	ui.applyLayoutPreset(ui.currentLayout)
	ui.rebuildLayout()
}

// applyLayoutPreset applies a specific layout configuration
func (ui *UI) applyLayoutPreset(preset int) {
	// Reset all panels visibility
	for _, p := range ui.panels {
		p.visible = false
	}
	
	switch preset {
	case 0: // Default - balanced view
		ui.setPanelVisibility("interfaces", true)
		ui.setPanelVisibility("stats", true)
		ui.setPanelVisibility("traffic", true)
		ui.setPanelVisibility("connections", true)
		ui.setPanelVisibility("details", true)
		
	case 1: // Compact - essential info only
		ui.setPanelVisibility("interfaces", true)
		ui.setPanelVisibility("traffic", true)
		ui.setPanelVisibility("connections", true)
		
	case 2: // Detailed - all information
		ui.setPanelVisibility("interfaces", true)
		ui.setPanelVisibility("stats", true)
		ui.setPanelVisibility("traffic", true)
		ui.setPanelVisibility("protocol", true)
		ui.setPanelVisibility("connections", true)
		ui.setPanelVisibility("details", true)
		ui.setPanelVisibility("servicePie", true)
		ui.setPanelVisibility("protocolPie", true)
		
	case 3: // Minimal - just graphs
		ui.setPanelVisibility("traffic", true)
		ui.setPanelVisibility("connections", true)
	}
}

// setPanelVisibility sets visibility for a specific panel
func (ui *UI) setPanelVisibility(id string, visible bool) {
	for _, p := range ui.panels {
		if p.id == id {
			p.visible = visible
			break
		}
	}
}

// decreaseUpdateInterval makes updates faster
func (ui *UI) decreaseUpdateInterval() {
	if ui.updateInterval > 500*time.Millisecond {
		ui.updateInterval -= 250 * time.Millisecond
		ui.updateStatusBar()
	}
}

// increaseUpdateInterval makes updates slower
func (ui *UI) increaseUpdateInterval() {
	if ui.updateInterval < 10*time.Second {
		ui.updateInterval += 250 * time.Millisecond
		ui.updateStatusBar()
	}
}

// selectNextInterface selects the next network interface
func (ui *UI) selectNextInterface() {
	count := ui.interfaceList.GetItemCount()
	if count == 0 {
		return
	}
	current := ui.interfaceList.GetCurrentItem()
	next := (current + 1) % count
	ui.interfaceList.SetCurrentItem(next)
}

// selectPreviousInterface selects the previous network interface
func (ui *UI) selectPreviousInterface() {
	count := ui.interfaceList.GetItemCount()
	if count == 0 {
		return
	}
	current := ui.interfaceList.GetCurrentItem()
	prev := current - 1
	if prev < 0 {
		prev = count - 1
	}
	ui.interfaceList.SetCurrentItem(prev)
}

// cycleGraphStyle cycles through available graph rendering styles
func (ui *UI) cycleGraphStyle() {
	styles := []graph.GraphStyle{graph.StyleBraille, graph.StyleBlock, graph.StyleTTY}
	currentIdx := 0
	for i, s := range styles {
		if s == ui.graphStyle {
			currentIdx = i
			break
		}
	}
	ui.graphStyle = styles[(currentIdx+1)%len(styles)]
	
	// Apply to all graphs
	if ui.trafficGraph != nil {
		for _, gw := range ui.trafficGraph.GraphWidgets() {
			if gw != nil {
				gw.SetStyle(ui.graphStyle)
			}
		}
	}
}

// showExportMenu shows data export options
func (ui *UI) showExportMenu() {
	modal := tview.NewModal().
		SetText("Export to: ").
		AddButtons([]string{"CSV", "JSON", "Cancel"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			switch buttonIndex {
			case 0: // CSV
				// TODO: Implement CSV export
			case 1: // JSON
				// TODO: Implement JSON export
			}
			ui.pages.RemovePage("export")
		})
	ui.pages.AddPage("export", modal, true, true)
}

// clearFilters clears all active filters
func (ui *UI) clearFilters() {
	ui.filterString = ""
	ui.bpfString = ""
	ui.updateData()
}

// togglePause pauses/resumes data updates
func (ui *UI) togglePause() {
	ui.paused = !ui.paused
	ui.updateStatusBar()
}

// setupMouseHandlers adds mouse click handlers to UI elements
func (ui *UI) setupMouseHandlers() {
	// Add mouse handler for connection table
	ui.connectionTable.SetMouseCapture(func(action tview.MouseAction, event *tcell.EventMouse) (tview.MouseAction, *tcell.EventMouse) {
		if action == tview.MouseLeftClick {
			row, _ := ui.connectionTable.GetSelection()
			if row > 0 && row-1 < len(ui.connections) {
				ui.selectedConnection = ui.connections[row-1]
				ui.showConnectionDetails(ui.selectedConnection)
			}
		} else if action == tview.MouseRightClick {
			// Show context menu for connection
			row, _ := ui.connectionTable.GetSelection()
			if row > 0 && row-1 < len(ui.connections) {
				ui.showConnectionContextMenu(row - 1)
			}
		} else if action == tview.MouseLeftDoubleClick {
			// Double-click to show packet details
			if ui.selectedConnection != nil {
				ui.showConnectionPacketsPage()
			}
		}
		return action, event
	})
	
	// Add clickable titles to panels
	ui.setupClickablePanelTitles()
	
	// Add mouse wheel support for interface list
	ui.interfaceList.SetMouseCapture(func(action tview.MouseAction, event *tcell.EventMouse) (tview.MouseAction, *tcell.EventMouse) {
		if action == tview.MouseScrollUp {
			ui.selectPreviousInterface()
		} else if action == tview.MouseScrollDown {
			ui.selectNextInterface()
		}
		return action, event
	})
}

// setupClickablePanelTitles makes panel titles clickable to toggle visibility
func (ui *UI) setupClickablePanelTitles() {
	// Make the traffic graph title clickable to cycle graph styles
	ui.trafficGraph.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		return event
	})
	
	ui.trafficGraph.SetMouseCapture(func(action tview.MouseAction, event *tcell.EventMouse) (tview.MouseAction, *tcell.EventMouse) {
		if action == tview.MouseLeftClick {
			x, y := event.Position()
			_, titleY, width, _ := ui.trafficGraph.GetRect()
			// Check if click is on the title bar
			if y == titleY && x > 0 && x < width {
				ui.cycleGraphStyle()
			}
		}
		return action, event
	})
}

// showConnectionContextMenu displays a context menu for a connection
func (ui *UI) showConnectionContextMenu(connIndex int) {
	if connIndex < 0 || connIndex >= len(ui.connections) {
		return
	}
	
	conn := ui.connections[connIndex]
	modal := tview.NewModal().
		SetText(fmt.Sprintf("Connection: %s:%d → %s:%d", 
			conn.SrcIP, conn.SrcPort, conn.DstIP, conn.DstPort)).
		AddButtons([]string{"View Packets", "Export", "Block", "Cancel"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			switch buttonIndex {
			case 0: // View Packets
				ui.selectedConnection = conn
				ui.showConnectionPacketsPage()
			case 1: // Export
				// TODO: Export connection data
			case 2: // Block
				// TODO: Block connection
			}
			ui.pages.RemovePage("connMenu")
		})
	ui.pages.AddPage("connMenu", modal, true, true)
}

// showKillConnectionDialog shows a confirmation dialog for killing a connection
func (ui *UI) showKillConnectionDialog() {
	if ui.selectedConnection == nil {
		return
	}
	
	modal := tview.NewModal().
		SetText(fmt.Sprintf("Kill connection %s:%d → %s:%d?", 
			ui.selectedConnection.SrcIP, ui.selectedConnection.SrcPort,
			ui.selectedConnection.DstIP, ui.selectedConnection.DstPort)).
		AddButtons([]string{"Kill", "Cancel"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			if buttonIndex == 0 {
				// TODO: Implement actual connection killing
				// For now, just remove from display
				ui.updateData()
			}
			ui.pages.RemovePage("killConn")
		})
	ui.pages.AddPage("killConn", modal, true, true)
}

// showConnectionExportMenu shows export options for connection data
func (ui *UI) showConnectionExportMenu() {
	if ui.selectedConnection == nil {
		return
	}
	
	modal := tview.NewModal().
		SetText("Export connection data as:").
		AddButtons([]string{"CSV", "JSON", "PCAP", "Cancel"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			switch buttonIndex {
			case 0: // CSV
				ui.exportConnectionCSV()
			case 1: // JSON
				ui.exportConnectionJSON()
			case 2: // PCAP
				ui.exportConnectionPCAP()
			}
			ui.pages.RemovePage("exportConn")
		})
	ui.pages.AddPage("exportConn", modal, true, true)
}

// toggleConnectionMark marks/unmarks a connection for bulk operations
func (ui *UI) toggleConnectionMark() {
	if ui.selectedConnection == nil {
		return
	}
	
	connKey := fmt.Sprintf("%s:%d-%s:%d-%s", 
		ui.selectedConnection.SrcIP, ui.selectedConnection.SrcPort,
		ui.selectedConnection.DstIP, ui.selectedConnection.DstPort,
		ui.selectedConnection.Protocol)
	
	if ui.markedConnections[connKey] {
		delete(ui.markedConnections, connKey)
	} else {
		ui.markedConnections[connKey] = true
	}
	
	ui.updateConnectionTable()
}

// selectAllConnections marks all visible connections
func (ui *UI) selectAllConnections() {
	for _, conn := range ui.connections {
		connKey := fmt.Sprintf("%s:%d-%s:%d-%s", 
			conn.SrcIP, conn.SrcPort,
			conn.DstIP, conn.DstPort,
			conn.Protocol)
		ui.markedConnections[connKey] = true
	}
	ui.updateConnectionTable()
}

// exportConnectionCSV exports connection data to CSV
func (ui *UI) exportConnectionCSV() {
	// TODO: Implement CSV export
	ui.showError("CSV export not yet implemented")
}

// exportConnectionJSON exports connection data to JSON
func (ui *UI) exportConnectionJSON() {
	// TODO: Implement JSON export
	ui.showError("JSON export not yet implemented")
}

// exportConnectionPCAP exports connection packets to PCAP
func (ui *UI) exportConnectionPCAP() {
	// TODO: Implement PCAP export
	ui.showError("PCAP export not yet implemented")
}

// getConnectionKey returns a unique key for a connection
func getConnectionKey(conn *netcap.Connection) string {
	return fmt.Sprintf("%s:%d-%s:%d-%s", 
		conn.SrcIP, conn.SrcPort,
		conn.DstIP, conn.DstPort,
		conn.Protocol)
}

// generateSparkline creates a mini ASCII graph for connection activity
func generateSparkline(values []float64, width int) string {
	if len(values) == 0 || width <= 0 {
		return ""
	}
	
	// Unicode block characters for sparklines
	blocks := []rune{' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}
	
	// Find min and max values
	min, max := values[0], values[0]
	for _, v := range values {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	
	// Handle case where all values are the same
	if max == min {
		if max == 0 {
			return strings.Repeat(string(blocks[0]), width)
		}
		return strings.Repeat(string(blocks[4]), width)
	}
	
	// Sample or interpolate values to fit width
	sparkline := make([]rune, width)
	for i := 0; i < width; i++ {
		// Map position to value index
		valueIdx := int(float64(i) * float64(len(values)-1) / float64(width-1))
		if valueIdx >= len(values) {
			valueIdx = len(values) - 1
		}
		
		// Normalize value to 0-8 range
		normalized := (values[valueIdx] - min) / (max - min)
		blockIdx := int(normalized * 8)
		if blockIdx > 8 {
			blockIdx = 8
		}
		if blockIdx < 0 {
			blockIdx = 0
		}
		
		sparkline[i] = blocks[blockIdx]
	}
	
	return string(sparkline)
}

// getConnectionSparkline returns a sparkline for the connection's bandwidth history
func (ui *UI) getConnectionSparkline(connKey string) string {
	history, exists := ui.connectionHistory[connKey]
	if !exists || len(history) == 0 {
		return "        " // Empty sparkline
	}
	
	// Keep only recent history (last 20 points)
	if len(history) > 20 {
		history = history[len(history)-20:]
		ui.connectionHistory[connKey] = history
	}
	
	return generateSparkline(history, 8) // 8-character wide sparkline
}

// updateConnectionHistory updates the bandwidth history for connections
func (ui *UI) updateConnectionHistory() {
	for _, conn := range ui.connections {
		connKey := getConnectionKey(conn)
		
		// Initialize history if needed
		if _, exists := ui.connectionHistory[connKey]; !exists {
			ui.connectionHistory[connKey] = make([]float64, 0, 20)
		}
		
		// Add current size as the data point (we'll track growth over time)
		ui.connectionHistory[connKey] = append(ui.connectionHistory[connKey], float64(conn.Size))
		
		// Limit history size
		if len(ui.connectionHistory[connKey]) > 20 {
			ui.connectionHistory[connKey] = ui.connectionHistory[connKey][1:]
		}
	}
	
	// Clean up old connections not seen in last update
	for key := range ui.connectionHistory {
		found := false
		for _, conn := range ui.connections {
			if getConnectionKey(conn) == key {
				found = true
				break
			}
		}
		if !found {
			// Keep history for a bit in case connection comes back
			if len(ui.connectionHistory[key]) > 0 {
				// Add a zero to show inactivity
				ui.connectionHistory[key] = append(ui.connectionHistory[key], 0)
				if len(ui.connectionHistory[key]) > 20 {
					ui.connectionHistory[key] = ui.connectionHistory[key][1:]
				}
			}
		}
	}
}

// toggleRecording starts or stops session recording
func (ui *UI) toggleRecording() {
	if ui.recording {
		// Stop recording
		ui.stopRecording()
	} else {
		// Start recording
		ui.startRecording()
	}
}

// startRecording begins recording network session
func (ui *UI) startRecording() {
	ui.recording = true
	ui.recordingStart = time.Now()
	ui.sessionData = &SessionRecording{
		StartTime: ui.recordingStart,
		Interface: ui.selectedIface,
		Snapshots: make([]NetworkSnapshot, 0),
		Events:    make([]SessionEvent, 0),
	}
	
	// Add start event
	ui.recordEvent("recording_started", fmt.Sprintf("Started recording on interface %s", ui.selectedIface))
	
	// Update status bar to show recording
	ui.updateStatusBar()
	
	// Show notification
	ui.showNotification("Recording started", 2*time.Second)
}

// stopRecording stops recording and saves the session
func (ui *UI) stopRecording() {
	if !ui.recording || ui.sessionData == nil {
		return
	}
	
	ui.recording = false
	ui.sessionData.EndTime = time.Now()
	
	// Add stop event
	ui.recordEvent("recording_stopped", "Recording stopped")
	
	// Calculate totals
	if stats, ok := ui.networkMonitor.GetInterfaceStats()[ui.selectedIface]; ok {
		ui.sessionData.TotalBytes = stats.BytesIn + stats.BytesOut
		ui.sessionData.PacketCount = int(stats.PacketsIn + stats.PacketsOut)
	}
	
	// Save recording
	ui.showSaveRecordingDialog()
	
	// Update status bar
	ui.updateStatusBar()
}

// recordSnapshot captures current network state
func (ui *UI) recordSnapshot() {
	if !ui.recording || ui.sessionData == nil {
		return
	}
	
	snapshot := NetworkSnapshot{
		Timestamp:   time.Now(),
		Connections: ui.connections,
		Stats:       ui.networkMonitor.GetInterfaceStats(),
		BandwidthIn: 0,
		BandwidthOut: 0,
	}
	
	// Get current bandwidth
	in, out := ui.getNetworkRates()
	snapshot.BandwidthIn = in
	snapshot.BandwidthOut = out
	
	ui.sessionData.Snapshots = append(ui.sessionData.Snapshots, snapshot)
}

// recordEvent adds an event to the recording
func (ui *UI) recordEvent(eventType, details string) {
	if !ui.recording || ui.sessionData == nil {
		return
	}
	
	event := SessionEvent{
		Timestamp: time.Now(),
		Type:      eventType,
		Details:   details,
	}
	
	ui.sessionData.Events = append(ui.sessionData.Events, event)
}

// showSaveRecordingDialog shows dialog to save recording
func (ui *UI) showSaveRecordingDialog() {
	// Create input field for filename
	input := tview.NewInputField().
		SetLabel("Save recording as: ").
		SetText(fmt.Sprintf("nsd_session_%s.json", time.Now().Format("20060102_150405"))).
		SetFieldWidth(40)
	
	input.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			filename := input.GetText()
			if filename != "" {
				err := ui.saveRecording(filename)
				if err != nil {
					ui.showError(fmt.Sprintf("Failed to save recording: %v", err))
				} else {
					ui.showNotification(fmt.Sprintf("Recording saved to %s", filename), 3*time.Second)
				}
			}
			ui.pages.RemovePage("saveRecording")
		} else if key == tcell.KeyEscape {
			ui.pages.RemovePage("saveRecording")
		}
	})
	
	flex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(nil, 0, 1, false).
		AddItem(input, 3, 0, true).
		AddItem(nil, 0, 1, false)
	
	ui.pages.AddPage("saveRecording", flex, true, true)
	ui.app.SetFocus(input)
}

// saveRecording saves the recording to a file
func (ui *UI) saveRecording(filename string) error {
	if ui.sessionData == nil {
		return fmt.Errorf("no recording data")
	}
	
	data, err := json.MarshalIndent(ui.sessionData, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(filename, data, 0644)
}

// showReplayMenu shows menu to load and replay sessions
func (ui *UI) showReplayMenu() {
	// List JSON files in current directory
	files, err := filepath.Glob("nsd_session_*.json")
	if err != nil || len(files) == 0 {
		ui.showError("No session recordings found")
		return
	}
	
	list := tview.NewList()
	for _, file := range files {
		info, _ := os.Stat(file)
		list.AddItem(file, fmt.Sprintf("Size: %d bytes", info.Size()), 0, nil)
	}
	
	list.SetSelectedFunc(func(index int, mainText, secondaryText string, shortcut rune) {
		ui.loadAndReplaySession(mainText)
		ui.pages.RemovePage("replayMenu")
	})
	
	list.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			ui.pages.RemovePage("replayMenu")
			return nil
		}
		return event
	})
	
	list.SetBorder(true).SetTitle("Select Session to Replay")
	ui.pages.AddPage("replayMenu", list, true, true)
}

// loadAndReplaySession loads and replays a recorded session
func (ui *UI) loadAndReplaySession(filename string) {
	data, err := os.ReadFile(filename)
	if err != nil {
		ui.showError(fmt.Sprintf("Failed to load session: %v", err))
		return
	}
	
	var session SessionRecording
	if err := json.Unmarshal(data, &session); err != nil {
		ui.showError(fmt.Sprintf("Failed to parse session: %v", err))
		return
	}
	
	// Start replay
	go ui.replaySession(&session)
}

// replaySession replays a recorded session
func (ui *UI) replaySession(session *SessionRecording) {
	ui.paused = true
	defer func() { ui.paused = false }()
	
	// Show replay notification
	ui.app.QueueUpdateDraw(func() {
		ui.showNotification(fmt.Sprintf("Replaying session from %s", session.StartTime.Format("2006-01-02 15:04:05")), 3*time.Second)
	})
	
	// Replay snapshots with timing
	for i, snapshot := range session.Snapshots {
		// Calculate delay
		var delay time.Duration
		if i > 0 {
			delay = snapshot.Timestamp.Sub(session.Snapshots[i-1].Timestamp)
			// Cap delay at 5 seconds to avoid long waits
			if delay > 5*time.Second {
				delay = 5 * time.Second
			}
		}
		
		time.Sleep(delay)
		
		// Update UI with snapshot data
		ui.app.QueueUpdateDraw(func() {
			ui.connections = snapshot.Connections
			ui.updateConnectionTable()
			ui.updateStatsView()
			ui.updateStatusBar()
		})
	}
	
	ui.app.QueueUpdateDraw(func() {
		ui.showNotification("Replay complete", 2*time.Second)
	})
}

// showNotification displays a temporary notification
func (ui *UI) showNotification(message string, duration time.Duration) {
	notification := tview.NewTextView().
		SetText(message).
		SetTextAlign(tview.AlignCenter).
		SetTextColor(ui.theme.PrimaryColor)
	
	notification.SetBorder(true).
		SetBorderColor(ui.theme.BorderColor).
		SetBackgroundColor(ui.theme.StatusBarBgColor)
	
	// Create a small centered modal
	flex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().
			AddItem(nil, 0, 1, false).
			AddItem(notification, 40, 0, false).
			AddItem(nil, 0, 1, false), 3, 0, false).
		AddItem(nil, 0, 1, false)
	
	ui.pages.AddPage("notification", flex, true, false)
	
	// Auto-remove after duration
	go func() {
		time.Sleep(duration)
		ui.app.QueueUpdateDraw(func() {
			ui.pages.RemovePage("notification")
		})
	}()
}

// showAdvancedFilterDialog shows the advanced filter dialog
func (ui *UI) showAdvancedFilterDialog() {
    form := tview.NewForm()
    
    // Filter presets
    presets := []string{"Custom", "HTTP/HTTPS Only", "DNS Only", "Large Transfers (>1MB)", "Active Now", "Local Network Only"}
    
    // Filter fields
    var (
        srcIPFilter    string
        dstIPFilter    string
        portFilter     string
        protocolFilter string
        serviceFilter  string
        minSizeFilter  string
        maxSizeFilter  string
    )
    
    // Parse existing filter if any
    if ui.filterString != "" {
        // Simple parsing - could be enhanced
        srcIPFilter = ui.filterString
    }
    
    form.
        AddDropDown("Filter Preset", presets, 0, func(option string, index int) {
            switch index {
            case 1: // HTTP/HTTPS Only
                serviceFilter = "HTTP,HTTPS"
                form.GetFormItemByLabel("Service").(*tview.InputField).SetText(serviceFilter)
            case 2: // DNS Only
                serviceFilter = "DNS"
                portFilter = "53"
                form.GetFormItemByLabel("Service").(*tview.InputField).SetText(serviceFilter)
                form.GetFormItemByLabel("Port").(*tview.InputField).SetText(portFilter)
            case 3: // Large Transfers
                minSizeFilter = "1048576" // 1MB
                form.GetFormItemByLabel("Min Size (bytes)").(*tview.InputField).SetText(minSizeFilter)
            case 4: // Active Now
                // Will be handled in filter logic
            case 5: // Local Network Only
                srcIPFilter = "192.168.*,10.*,172.16.*"
                form.GetFormItemByLabel("Source IP").(*tview.InputField).SetText(srcIPFilter)
            }
        }).
        AddInputField("Source IP", srcIPFilter, 30, nil, func(text string) {
            srcIPFilter = text
        }).
        AddInputField("Dest IP", dstIPFilter, 30, nil, func(text string) {
            dstIPFilter = text
        }).
        AddInputField("Port", portFilter, 15, nil, func(text string) {
            portFilter = text
        }).
        AddInputField("Protocol", protocolFilter, 15, nil, func(text string) {
            protocolFilter = text
        }).
        AddInputField("Service", serviceFilter, 20, nil, func(text string) {
            serviceFilter = text
        }).
        AddInputField("Min Size (bytes)", minSizeFilter, 15, nil, func(text string) {
            minSizeFilter = text
        }).
        AddInputField("Max Size (bytes)", maxSizeFilter, 15, nil, func(text string) {
            maxSizeFilter = text
        }).
        AddButton("Apply", func() {
            // Build filter string
            filter := ui.buildAdvancedFilter(srcIPFilter, dstIPFilter, portFilter, 
                protocolFilter, serviceFilter, minSizeFilter, maxSizeFilter)
            ui.filterString = filter
            ui.updateConnectionTable()
            ui.pages.RemovePage("advancedFilter")
        }).
        AddButton("Clear All", func() {
            ui.filterString = ""
            ui.updateConnectionTable()
            ui.pages.RemovePage("advancedFilter")
        }).
        AddButton("Cancel", func() {
            ui.pages.RemovePage("advancedFilter")
        })
    
    form.SetBorder(true).SetTitle("Advanced Filters").SetTitleAlign(tview.AlignCenter)
    
    // Center the form
    flex := tview.NewFlex().
        SetDirection(tview.FlexRow).
        AddItem(nil, 0, 1, false).
        AddItem(tview.NewFlex().
            AddItem(nil, 0, 1, false).
            AddItem(form, 60, 0, true).
            AddItem(nil, 0, 1, false), 25, 0, true).
        AddItem(nil, 0, 1, false)
    
    ui.pages.AddPage("advancedFilter", flex, true, true)
}

// buildAdvancedFilter builds a filter string from components
func (ui *UI) buildAdvancedFilter(srcIP, dstIP, port, protocol, service, minSize, maxSize string) string {
    var filters []string
    
    if srcIP != "" {
        filters = append(filters, fmt.Sprintf("src:%s", srcIP))
    }
    if dstIP != "" {
        filters = append(filters, fmt.Sprintf("dst:%s", dstIP))
    }
    if port != "" {
        filters = append(filters, fmt.Sprintf("port:%s", port))
    }
    if protocol != "" {
        filters = append(filters, fmt.Sprintf("proto:%s", protocol))
    }
    if service != "" {
        filters = append(filters, fmt.Sprintf("svc:%s", service))
    }
    if minSize != "" {
        filters = append(filters, fmt.Sprintf("size>%s", minSize))
    }
    if maxSize != "" {
        filters = append(filters, fmt.Sprintf("size<%s", maxSize))
    }
    
    return strings.Join(filters, " ")
}

// matchesAdvancedFilter checks if a connection matches the advanced filter
func (ui *UI) matchesAdvancedFilter(conn *netcap.Connection, filter string) bool {
    if filter == "" {
        return true
    }
    
    // Parse filter components
    parts := strings.Fields(filter)
    for _, part := range parts {
        if !ui.matchesFilterPart(conn, part) {
            return false
        }
    }
    
    return true
}

// matchesFilterPart checks if a connection matches a single filter part
func (ui *UI) matchesFilterPart(conn *netcap.Connection, part string) bool {
    // Handle key:value filters
    if strings.Contains(part, ":") {
        kv := strings.SplitN(part, ":", 2)
        if len(kv) != 2 {
            return true
        }
        
        key, value := kv[0], kv[1]
        switch key {
        case "src":
            return ui.matchesIPPattern(conn.SrcIP.String(), value)
        case "dst":
            return ui.matchesIPPattern(conn.DstIP.String(), value)
        case "port":
            ports := strings.Split(value, ",")
            for _, p := range ports {
                if fmt.Sprintf("%d", conn.SrcPort) == p || fmt.Sprintf("%d", conn.DstPort) == p {
                    return true
                }
            }
            return false
        case "proto":
            return strings.EqualFold(conn.Protocol, value)
        case "svc":
            services := strings.Split(value, ",")
            for _, s := range services {
                if strings.EqualFold(conn.Service, s) {
                    return true
                }
            }
            return false
        }
    }
    
    // Handle size comparisons
    if strings.HasPrefix(part, "size>") {
        size, err := strconv.ParseUint(part[5:], 10, 64)
        if err == nil {
            return conn.Size > size
        }
    }
    if strings.HasPrefix(part, "size<") {
        size, err := strconv.ParseUint(part[5:], 10, 64)
        if err == nil {
            return conn.Size < size
        }
    }
    
    // Default text search (legacy)
    return strings.Contains(strings.ToLower(conn.SrcIP.String()), strings.ToLower(part)) ||
           strings.Contains(strings.ToLower(conn.DstIP.String()), strings.ToLower(part)) ||
           strings.Contains(strings.ToLower(conn.Service), strings.ToLower(part))
}

// matchesIPPattern checks if an IP matches a pattern (supports wildcards)
func (ui *UI) matchesIPPattern(ip, pattern string) bool {
    patterns := strings.Split(pattern, ",")
    for _, p := range patterns {
        p = strings.TrimSpace(p)
        if strings.Contains(p, "*") {
            // Convert wildcard to simple prefix match
            prefix := strings.TrimSuffix(p, "*")
            if strings.HasPrefix(ip, prefix) {
                return true
            }
        } else if ip == p {
            return true
        }
    }
    return false
}

// getProfilesDir returns the directory for storing UI profiles
func (ui *UI) getProfilesDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(homeDir, ".config", "nsd", "profiles")
}

// saveProfile saves the current UI configuration to a profile
func (ui *UI) saveProfile(name string) error {
	profile := UIProfile{
		Name:            name,
		Theme:           ui.getCurrentThemeName(),
		BorderStyle:     ui.borderStyle,
		BorderAnimation: ui.borderAnimation,
		LayoutPreset:    ui.currentLayout,
		UpdateInterval:  fmt.Sprintf("%.1fs", ui.updateInterval.Seconds()),
		GraphStyle:      fmt.Sprintf("%d", ui.graphStyle),
		PanelStates:     make(map[string]bool),
		GradientEnabled: true, // Will be updated from actual graph settings
		ShowLegend:      true, // Will be updated from actual graph settings
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	
	// Save panel visibility states
	for _, panel := range ui.panels {
		profile.PanelStates[panel.id] = panel.visible
	}
	
	// Get graph settings
	// Note: Currently using default values as GraphWidget doesn't expose these methods
	// TODO: Add methods to GraphWidget to get gradient and legend status
	
	// Create profiles directory if it doesn't exist
	profilesDir := ui.getProfilesDir()
	if err := os.MkdirAll(profilesDir, 0755); err != nil {
		return fmt.Errorf("failed to create profiles directory: %w", err)
	}
	
	// Save profile to JSON file
	filename := filepath.Join(profilesDir, name+".json")
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal profile: %w", err)
	}
	
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write profile file: %w", err)
	}
	
	return nil
}

// loadProfile loads a UI profile and applies it
func (ui *UI) loadProfile(name string) error {
	profilesDir := ui.getProfilesDir()
	filename := filepath.Join(profilesDir, name+".json")
	
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read profile file: %w", err)
	}
	
	var profile UIProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return fmt.Errorf("failed to unmarshal profile: %w", err)
	}
	
	// Apply theme
	if theme, exists := Themes[profile.Theme]; exists {
		ui.theme = theme
		ui.theme.calculateGradients()
		ui.applyTheme()
	}
	
	// Apply border settings
	ui.borderStyle = profile.BorderStyle
	ui.borderAnimation = profile.BorderAnimation
	ui.updateAnimationTicker()
	
	// Apply layout preset
	ui.currentLayout = profile.LayoutPreset
	ui.applyLayoutPreset(ui.currentLayout)
	
	// Apply update interval
	if duration, err := time.ParseDuration(profile.UpdateInterval); err == nil {
		ui.updateInterval = duration
		ui.updateStatusBar()
	}
	
	// Apply graph style
	switch profile.GraphStyle {
	case "0":
		ui.graphStyle = graph.StyleBraille
	case "1":
		ui.graphStyle = graph.StyleBlock
	case "2":
		ui.graphStyle = graph.StyleTTY
	}
	
	// Apply panel visibility states
	for _, panel := range ui.panels {
		if visible, exists := profile.PanelStates[panel.id]; exists {
			panel.visible = visible
		}
	}
	
	// Apply graph settings
	if ui.trafficGraph != nil {
		for _, gw := range ui.trafficGraph.GraphWidgets() {
			if gw != nil {
				gw.SetStyle(ui.graphStyle)
				gw.SetGradientEnabled(profile.GradientEnabled)
				gw.ShowLegend(profile.ShowLegend)
			}
		}
	}
	
	// Rebuild layout to apply all changes
	ui.rebuildLayout()
	
	return nil
}

// listProfiles returns a list of available profile names
func (ui *UI) listProfiles() []string {
	profilesDir := ui.getProfilesDir()
	files, err := os.ReadDir(profilesDir)
	if err != nil {
		return []string{}
	}
	
	var profiles []string
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") {
			name := strings.TrimSuffix(file.Name(), ".json")
			profiles = append(profiles, name)
		}
	}
	
	sort.Strings(profiles)
	return profiles
}

// showProfilesMenu displays a menu for saving/loading profiles
func (ui *UI) showProfilesMenu() {
	profiles := ui.listProfiles()
	
	list := tview.NewList()
	list.SetBorder(true).SetTitle("UI Profiles").SetTitleAlign(tview.AlignCenter)
	
	// Add save option
	list.AddItem("Save Current Profile...", "Save current UI configuration", 's', func() {
		ui.showSaveProfileDialog()
	})
	
	// Add separator
	list.AddItem("", "--- Saved Profiles ---", 0, nil)
	
	// Add existing profiles
	for _, profile := range profiles {
		p := profile // Capture for closure
		list.AddItem(fmt.Sprintf("Load: %s", p), "Load this profile", 0, func() {
			if err := ui.loadProfile(p); err != nil {
				ui.showError(fmt.Sprintf("Failed to load profile: %v", err))
			} else {
				ui.pages.RemovePage("profiles")
			}
		})
	}
	
	// Add cancel option
	list.AddItem("", "", 0, nil)
	list.AddItem("Cancel", "Return to main screen", 'c', func() {
		ui.pages.RemovePage("profiles")
	})
	
	list.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			ui.pages.RemovePage("profiles")
			return nil
		}
		return event
	})
	
	ui.pages.AddPage("profiles", list, true, true)
}

// showSaveProfileDialog shows a dialog for saving a new profile
func (ui *UI) showSaveProfileDialog() {
	form := tview.NewForm()
	var profileName string
	
	form.AddInputField("Profile Name", "", 30, nil, func(text string) {
		profileName = text
	})
	
	form.AddButton("Save", func() {
		if profileName == "" {
			ui.showError("Profile name cannot be empty")
			return
		}
		if err := ui.saveProfile(profileName); err != nil {
			ui.showError(fmt.Sprintf("Failed to save profile: %v", err))
		} else {
			ui.pages.RemovePage("save-profile")
			ui.pages.RemovePage("profiles")
		}
	})
	
	form.AddButton("Cancel", func() {
		ui.pages.RemovePage("save-profile")
	})
	
	form.SetBorder(true).SetTitle("Save Profile").SetTitleAlign(tview.AlignCenter)
	form.SetButtonsAlign(tview.AlignCenter)
	
	form.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			ui.pages.RemovePage("save-profile")
			return nil
		}
		return event
	})
	
	// Center the form
	flex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().
			AddItem(nil, 0, 1, false).
			AddItem(form, 50, 0, true).
			AddItem(nil, 0, 1, false), 10, 0, true).
		AddItem(nil, 0, 1, false)
	
	ui.pages.AddPage("save-profile", flex, true, true)
}

// SetStartupVisualization sets a visualization to show on startup
func (ui *UI) SetStartupVisualization(vizID string, fullscreen bool) {
	ui.startupVizID = vizID
	ui.startupFullscreen = fullscreen
}

// SetStartupDashboard sets a dashboard to show on startup
func (ui *UI) SetStartupDashboard(dashboardName string, fullscreen bool) {
	ui.startupDashboard = dashboardName
	ui.startupFullscreen = fullscreen
}

// LoadProfile loads a UI profile by name (public method for CLI)
func (ui *UI) LoadProfile(name string) error {
	return ui.loadProfile(name)
}

// showVisualizationFullscreen shows a single visualization in fullscreen
func (ui *UI) showVisualizationFullscreen(vizID string) {
	viz := GlobalRegistry.Get(vizID)
	if viz == nil {
		ui.showError(fmt.Sprintf("Visualization '%s' not found", vizID))
		return
	}
	
	viz.SetTheme(ui.theme)
	view := viz.CreateView()
	
	// Update visualization periodically
	go func() {
		ticker := time.NewTicker(ui.updateInterval)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				viz.Update(ui.networkMonitor)
				ui.app.Draw()
			case <-ui.stopChan:
				return
			}
		}
	}()
	
	// Handle input
	if inputHandler, ok := view.(interface{ SetInputCapture(func(*tcell.EventKey) *tcell.EventKey) }); ok {
		inputHandler.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
			switch event.Key() {
			case tcell.KeyEscape:
				ui.pages.SwitchToPage("main")
				return nil
			}
			
			switch event.Rune() {
			case 'q', 'Q':
				ui.app.Stop()
				return nil
			}
			
			return event
		})
	}
	
	ui.pages.AddAndSwitchToPage("viz-fullscreen", view, true)
}

// showDashboard shows a dashboard
func (ui *UI) showDashboard(layout DashboardLayout) {
	dashboard := NewDashboard(GlobalRegistry, ui.networkMonitor)
	dashboard.SetTheme(ui.theme)
	dashboard.SetLayout(layout)
	
	// Update dashboard periodically
	go func() {
		ticker := time.NewTicker(ui.updateInterval)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				dashboard.Update()
				ui.app.Draw()
			case <-ui.stopChan:
				return
			}
		}
	}()
	
	// Wrap in a container with controls
	container := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(dashboard, 0, 1, true).
		AddItem(ui.statusBar, 1, 0, false)
	
	container.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEscape:
			ui.pages.SwitchToPage("main")
			return nil
		}
		
		switch event.Rune() {
		case 'q', 'Q':
			ui.showExitMenu()
			return nil
		case 'd', 'D':
			ui.showDashboardMenu()
			return nil
		}
		
		return event
	})
	
	ui.pages.AddAndSwitchToPage("dashboard", container, true)
}

// showDashboardMenu shows the dashboard selection menu
func (ui *UI) showDashboardMenu() {
	list := tview.NewList()
	list.SetBorder(true).SetTitle("Dashboards").SetTitleAlign(tview.AlignCenter)
	
	// Add dashboard builder option
	list.AddItem("Create New Dashboard...", "Build a custom dashboard", 'n', func() {
		ui.showDashboardBuilder()
	})
	
	list.AddItem("", "--- Preset Dashboards ---", 0, nil)
	
	// Add preset dashboards
	dm := NewDashboardManager()
	for _, name := range dm.ListDashboards() {
		n := name // Capture for closure
		layout, _ := dm.GetDashboard(n)
		list.AddItem(layout.Name, layout.Description, 0, func() {
			ui.pages.RemovePage("dashboard-menu")
			ui.showDashboard(layout)
		})
	}
	
	// Add saved custom dashboards
	list.AddItem("", "--- Saved Dashboards ---", 0, nil)
	
	// TODO: Load saved dashboards from profile directory
	
	list.AddItem("", "", 0, nil)
	list.AddItem("Cancel", "Return to main view", 'c', func() {
		ui.pages.RemovePage("dashboard-menu")
	})
	
	list.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			ui.pages.RemovePage("dashboard-menu")
			return nil
		}
		return event
	})
	
	ui.pages.AddPage("dashboard-menu", list, true, true)
}

// showDashboardBuilder shows the dashboard builder interface
func (ui *UI) showDashboardBuilder() {
	builder := NewDashboardBuilder(ui.app, ui.networkMonitor, GlobalRegistry)
	builder.SetTheme(ui.theme)
	
	builder.SetOnSave(func(layout DashboardLayout) {
		// Save dashboard to profile
		profilesDir := ui.getProfilesDir()
		dashboardsDir := filepath.Join(profilesDir, "dashboards")
		
		if err := os.MkdirAll(dashboardsDir, 0755); err != nil {
			ui.showError(fmt.Sprintf("Failed to create dashboards directory: %v", err))
			return
		}
		
		// Generate filename
		filename := fmt.Sprintf("%s_%d.json", 
			strings.ReplaceAll(layout.Name, " ", "_"),
			time.Now().Unix())
		
		filepath := filepath.Join(dashboardsDir, filename)
		
		data, err := json.MarshalIndent(layout, "", "  ")
		if err != nil {
			ui.showError(fmt.Sprintf("Failed to marshal dashboard: %v", err))
			return
		}
		
		if err := os.WriteFile(filepath, data, 0644); err != nil {
			ui.showError(fmt.Sprintf("Failed to save dashboard: %v", err))
			return
		}
		
		ui.pages.RemovePage("dashboard-builder")
		ui.showDashboard(layout)
	})
	
	builder.SetOnCancel(func() {
		ui.pages.RemovePage("dashboard-builder")
	})
	
	ui.pages.AddPage("dashboard-builder", builder.GetView(), true, true)
}
