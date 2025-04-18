package ui

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/user/netmon/pkg/graph"
	"github.com/user/netmon/pkg/netcap"
	"github.com/user/netmon/pkg/utils"
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
	geoCache         map[string]string // cache IP->country code
	helpView         *tview.TextView  // Help screen view
	rawView         *tview.TextView  // raw packet hex view
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
}

// panel represents a UI section that can be toggled and positioned in the grid
type panel struct {
	id        string
	primitive tview.Primitive
	visible   bool
	row, col, rowSpan, colSpan int
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
		geoCache:       make(map[string]string),
	}

	ui.initComponents()
	ui.setupUI()
	// Initialize pie-chart panels
	ui.servicePieView = tview.NewTextView().SetDynamicColors(true)
	ui.servicePieView.SetBorder(true).SetBorderColor(ui.theme.PieBorderColor).SetTitleColor(ui.theme.PieTitleColor).SetTitle("Service Usage Pie [4]")
	ui.protocolPieView = tview.NewTextView().SetDynamicColors(true)
	ui.protocolPieView.SetBorder(true).SetBorderColor(ui.theme.PieBorderColor).SetTitleColor(ui.theme.PieTitleColor).SetTitle("Protocol Usage Pie [5]")
	ui.securePieView = tview.NewTextView().SetDynamicColors(true)
	ui.securePieView.SetBorder(true).SetBorderColor(ui.theme.PieBorderColor).SetTitleColor(ui.theme.PieTitleColor).SetTitle("Secure vs Nonsecure Pie [6]")
	// Interface counters page as table
	ui.ifaceStatsView = tview.NewTable().SetBorders(false)
	ui.ifaceStatsView.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitleColor(ui.theme.TitleColor).SetTitle("Interface Counters [I]")
	ui.ifaceStatsView.SetFixed(1, 0)
	// Packet size histogram view
	ui.histView = tview.NewTextView().SetDynamicColors(true)
	ui.histView.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitleColor(ui.theme.TitleColor).SetTitle("Packet Size Histogram [H]")
	// HTTP/DNS summary view
	ui.dnsHttpView = tview.NewTextView().SetDynamicColors(true)
	ui.dnsHttpView.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitleColor(ui.theme.TitleColor).SetTitle("HTTP/DNS Summary [D]")
	// Geo mapping view: will list remote IPs and country codes
	ui.geoView = tview.NewTable().SetBorders(false)
	ui.geoView.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitleColor(ui.theme.TitleColor).SetTitle("Geo Mapping [G]")
	ui.geoView.SetFixed(1, 0)
	// Help view
	ui.helpView = tview.NewTextView().SetDynamicColors(true).SetWrap(true)
	ui.helpView.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitleColor(ui.theme.TitleColor).SetTitle("Help [?]")
	// Raw packet hex view
	ui.rawView = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	ui.rawView.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitleColor(ui.theme.TitleColor).SetTitle("Raw Packet [Enter]")
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

// initComponents initializes all UI primitives
func (ui *UI) initComponents() {
	// Interface list
	ui.interfaceList = tview.NewList().ShowSecondaryText(false)
	ui.interfaceList.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitle("Interfaces")
	// Stats view
	ui.statsView = tview.NewTextView().SetDynamicColors(true)
	ui.statsView.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitle("Network Statistics [1]")
	// Traffic graph
	ui.trafficGraph = graph.NewMultiGraph()
	ui.trafficGraph.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitle("Network Traffic [2]")
	// Network graph widget
	ui.networkGraph = graph.NewGraphWidget()
	ui.networkGraph.SetTitle("Bandwidth").SetColor(ui.theme.PrimaryColor).SetSecondaryColor(ui.theme.SecondaryColor)
	ui.networkGraph.SetLabels("In", "Out").SetUnit("B/s")
	ui.networkGraph.SetDataFunc(ui.getNetworkRates).SetSampleInterval(1 * time.Second).SetHistoryDuration(2 * time.Minute)
	ui.trafficGraph.AddGraph(ui.networkGraph)
	// Protocol view
	ui.protocolView = tview.NewTextView().SetDynamicColors(true)
	ui.protocolView.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitle("Protocols [3]")
	// Connection table
	ui.connectionTable = tview.NewTable().SetBorders(false)
	ui.connectionTable.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitle("Connections [7]")
	ui.connectionTable.SetSelectable(true, false)
	// Detail view
	ui.detailView = tview.NewTextView().SetDynamicColors(true)
	ui.detailView.SetBorder(true).SetBorderColor(ui.theme.BorderColor).SetTitle("Connection Details [8]")
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

		// Handle runes
		switch event.Rune() {
		case 'q':
			ui.Stop()
			return nil
		case '?':
			name, _ := ui.pages.GetFrontPage()
			if name == "help" {
				ui.pages.SwitchToPage("main")
			} else {
				ui.showHelpPage()
			}
			return nil
		case 'r':
			ui.updateData()
			return nil
		case 's':
			ui.showSortOptions()
			return nil
		case 'f':
			ui.showFilterInput()
			return nil
		case 'b':
			ui.showBpfInput()
			return nil
		case 'p':
			// if focus is on connections table and a connection is selected, show its packets
			if ui.connectionTable.HasFocus() && ui.selectedConnection != nil {
				ui.showConnectionPacketsPage()
			} else {
				ui.showPacketBufferPage()
			}
			return nil
		case 'i':
			ui.showIfaceStatsPage()
			return nil
		case 'h':
			ui.showHistPage()
			return nil
		case 'd':
			ui.showDnsHttpPage()
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
			ui.showConnectionDetails(ui.selectedConnection)
		} else {
			ui.selectedConnection = nil
		}
	})
}

// rebuildLayout re-constructs the main page grid based on panel settings
func (ui *UI) rebuildLayout() {
    grid := tview.NewGrid().SetBorders(true)

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
	ui.updateConnectionTable()
	ui.updateProtocolView()
	ui.updatePieCharts()
	
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
    modal := tview.NewModal().SetText("Sort connections by:").
        AddButtons([]string{"Bytes", "Packets", "Last Seen", "Cancel"}).
        SetDoneFunc(func(_ int, label string) {
            if label != "Cancel" {
                switch label {
                case "Bytes":
                    ui.sortBy = "bytes"
                case "Packets":
                    ui.sortBy = "packets"
                case "Last Seen":
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
    form := tview.NewForm().
        AddInputField("Filter:", ui.filterString, 30, nil, func(text string) { ui.filterString = text }).
        AddButton("Apply", func() { ui.updateConnectionTable(); ui.pages.SwitchToPage("main") }).
        AddButton("Clear", func() { ui.filterString = ""; ui.updateConnectionTable(); ui.pages.SwitchToPage("main") }).
        AddButton("Cancel", func() { ui.pages.SwitchToPage("main") })
    form.SetBorder(true).SetTitle("Filter Connections").SetTitleAlign(tview.AlignCenter)
    ui.pages.AddPage("filter", form, true, true)
}

// showBpfInput displays an input form for setting BPF filter
func (ui *UI) showBpfInput() {
    form := tview.NewForm().
        AddInputField("BPF Filter:", ui.bpfString, 40, nil, func(text string) { ui.bpfString = text }).
        AddButton("Apply", func() { _ = ui.networkMonitor.SetBpfFilter(ui.selectedIface, ui.bpfString); ui.pages.SwitchToPage("main") }).
        AddButton("Clear", func() { ui.bpfString = ""; _ = ui.networkMonitor.SetBpfFilter(ui.selectedIface, ""); ui.pages.SwitchToPage("main") }).
        AddButton("Cancel", func() { ui.pages.SwitchToPage("main") })
    form.SetBorder(true).SetTitle("BPF Filter").SetTitleAlign(tview.AlignCenter)
    ui.pages.AddPage("bpf", form, true, true)
}

// showPacketBufferPage displays recent captured packets
func (ui *UI) showPacketBufferPage() {
    ui.pages.RemovePage("packets")
    packets := ui.networkMonitor.GetPacketBuffer()
    table := tview.NewTable().SetBorders(false)
    table.SetSelectable(true, false).SetFixed(1, 0)
    table.Select(1, 0)
    table.SetBorder(true).SetTitle("Captured Packets")
    headers := []string{"Time", "Source", "Destination", "Proto", "Service", "Length"}
    for i, h := range headers {
        table.SetCell(0, i, tview.NewTableCell(h).
            SetTextColor(tcell.ColorYellow).SetSelectable(false))
    }
    for r, p := range packets {
        row := r + 1
        table.SetCell(row, 0, tview.NewTableCell(p.Timestamp.Format("15:04:05")))
        table.SetCell(row, 1, tview.NewTableCell(fmt.Sprintf("%s:%d", p.SrcIP, p.SrcPort)))
        table.SetCell(row, 2, tview.NewTableCell(fmt.Sprintf("%s:%d", p.DstIP, p.DstPort)))
        table.SetCell(row, 3, tview.NewTableCell(p.Protocol))
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
    headers := []string{"Interface", "In (bytes/packets)", "Out (bytes/packets)", "PCAP Recv", "PCAP Drop", "PCAP IfDrop"}
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
        sb.WriteString("[yellow]No packets captured\n")
    } else {
        buckets := []int{64, 128, 256, 512, 1024, 1500}
        labels := []string{"<64", "64-127", "128-255", "256-511", "512-1023", ">=1024"}
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
        "[green]HTTP:[white] %d\n"+
        "[green]HTTPS:[white] %d\n"+
        "[green]DNS:[white] %d\n",
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

// showGeoPage displays remote IPs with country codes
func (ui *UI) showGeoPage() {
    ui.pages.RemovePage("geo")
    table := ui.geoView
    table.Clear()
    // header
    headers := []string{"Remote IP", "Country"}
    for i, h := range headers {
        table.SetCell(0, i, tview.NewTableCell(h).
            SetTextColor(tcell.ColorYellow).SetSelectable(false))
    }
    // gather connections for selected interface
    if ui.selectedIface == "" {
        ui.pages.AddPage("geo", table, true, true)
        ui.app.SetFocus(table)
        return
    }
    conns := ui.networkMonitor.GetConnections(ui.selectedIface)
    ips := make(map[string]struct{})
    for _, c := range conns {
        // determine remote IP
        var rip string
        if ui.networkMonitor.IsLocalAddress(c.SrcIP.String()) {
            rip = c.DstIP.String()
        } else {
            rip = c.SrcIP.String()
        }
        ips[rip] = struct{}{}
    }
    // sort
    keys := make([]string, 0, len(ips))
    for ip := range ips {
        keys = append(keys, ip)
    }
    sort.Strings(keys)
    // data rows
    for r, ip := range keys {
        code, ok := ui.geoCache[ip]
        if !ok {
            // fetch
            var res struct{CountryCode string `json:"countryCode"`}
            resp, err := http.Get("http://ip-api.com/json/" + ip + "?fields=countryCode")
            if err == nil {
                json.NewDecoder(resp.Body).Decode(&res)
                code = res.CountryCode
                resp.Body.Close()
            }
            if code == "" {
                code = "??"
            }
            ui.geoCache[ip] = code
        }
        row := r + 1
        table.SetCell(row, 0, tview.NewTableCell(ip))
        table.SetCell(row, 1, tview.NewTableCell(code))
    }
    table.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
        if event.Key() == tcell.KeyEscape {
            ui.pages.SwitchToPage("main")
            return nil
        }
        return event
    })
    ui.pages.AddPage("geo", table, true, true)
    ui.app.SetFocus(table)
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
        ui.statsView.SetText("[yellow]No statistics available")
        return
    }
    // compute current in/out rates
    inRate, outRate := ui.getNetworkRates()
    text := fmt.Sprintf(
        "[green]Interface:[white] %s\n\n"+
        "[green]In:[white] %s (%d pkts)\n"+
        "[green]Out:[white] %s (%d pkts)\n"+
        "[green]In Rate:[white] %s/s\n"+
        "[green]Out Rate:[white] %s/s\n\n"+
        "[green]Connections:[white] %d\n",
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
    headers := []string{"Source", "Destination", "Proto", "Svc", "Bytes", "Pkts", "Last Seen"}
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
        ui.connectionTable.SetCell(row, 0, tview.NewTableCell(c.SrcIP.String()).SetTextColor(ui.theme.PrimaryColor).SetExpansion(1))
        ui.connectionTable.SetCell(row, 1, tview.NewTableCell(c.DstIP.String()).SetTextColor(ui.theme.PrimaryColor).SetExpansion(1))
        ui.connectionTable.SetCell(row, 2, tview.NewTableCell(c.Protocol).SetTextColor(ui.theme.SecondaryColor).SetExpansion(1))
        ui.connectionTable.SetCell(row, 3, tview.NewTableCell(c.Service).SetTextColor(ui.theme.TitleColor).SetExpansion(1))
        ui.connectionTable.SetCell(row, 4, tview.NewTableCell(fmt.Sprintf("%d", c.Size)).SetTextColor(ui.theme.SecondaryColor).SetExpansion(1))
        ui.connectionTable.SetCell(row, 5, tview.NewTableCell(fmt.Sprintf("%d", c.Packets)).SetTextColor(ui.theme.PrimaryColor).SetExpansion(1))
        ui.connectionTable.SetCell(row, 6, tview.NewTableCell(c.LastSeen.Format(time.Kitchen)).SetTextColor(ui.theme.TitleColor).SetExpansion(1))
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
        "[green]Src:[white] %s:%d\n"+
        "[green]Dst:[white] %s:%d\n"+
        "[green]Proto:[white] %s\n"+
        "[green]Svc:[white] %s\n"+
        "[green]Bytes:[white] %s\n"+
        "[green]Pkts:[white] %d\n",
        c.SrcIP, c.SrcPort, c.DstIP, c.DstPort,
        c.Protocol, c.Service,
        utils.FormatBytes(c.Size), c.Packets,
    )
    // Find a packet for this connection
    buf := ui.networkMonitor.GetPacketBuffer()
    var hexDump string
    resetTag := colorTag(ui.theme.TitleColor)
    for _, p := range buf {
        if (fmt.Sprint(p.SrcIP) == fmt.Sprint(c.SrcIP) && fmt.Sprint(p.DstIP) == fmt.Sprint(c.DstIP) && p.SrcPort == c.SrcPort && p.DstPort == c.DstPort && p.Protocol == c.Protocol) ||
           (fmt.Sprint(p.SrcIP) == fmt.Sprint(c.DstIP) && fmt.Sprint(p.DstIP) == fmt.Sprint(c.SrcIP) && p.SrcPort == c.DstPort && p.DstPort == c.SrcPort && p.Protocol == c.Protocol) {
            // Format hex dump (first match)
            var sb strings.Builder
            dumpTag := colorTag(ui.theme.PrimaryColor)
            sb.WriteString(fmt.Sprintf("[%s]Hex Dump:[%s]\n", dumpTag, resetTag))
            data := p.Data
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
            hexDump = sb.String()
            break
        }
    }
    if hexDump != "" {
        text += "\n" + hexDump
    }
    ui.detailView.SetText(text)
}

// showError displays an error modal
func (ui *UI) showError(msg string) {
    modal := tview.NewModal().SetText(msg).
        AddButtons([]string{"OK"}).
        SetDoneFunc(func(_ int, _ string) { ui.pages.SwitchToPage("main") })
    ui.pages.AddPage("error", modal, true, true)
}

// startUpdateLoop starts periodic UI updates
func (ui *UI) startUpdateLoop() {
    ticker := time.NewTicker(ui.updateInterval)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            ui.app.QueueUpdateDraw(ui.updateData)
        case <-ui.stopChan:
            return
        }
    }
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
    for k := range counts {
        keys = append(keys, k)
    }
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
    helpText := `Keybindings:
q: quit
r: refresh
s: sort
f: filter
b: set BPF filter
p: raw packet buffer
i: interface stats
h: packet-size histogram
d: HTTP/DNS summary
g: geo mapping
0: toggle interfaces pane
?: toggle help
Esc: return to main`
    ui.helpView.SetText(helpText)
    ui.helpView.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
        if event.Key() == tcell.KeyEscape || event.Rune() == '?' {
            ui.pages.SwitchToPage("main")
            return nil
        }
        return event
    })
    ui.pages.AddPage("help", ui.helpView, true, true)
    ui.app.SetFocus(ui.helpView)
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

// Run starts the UI application
func (ui *UI) Run() error {
    ui.bpfString = ui.networkMonitor.GetFilterExpression()
    ui.populateInterfaceList()
    ui.networkGraph.Start()
    go ui.startUpdateLoop()
    ui.updateData()
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
    sb.WriteString(fmt.Sprintf("[%s]Hex Dump:[%s]\n", dumpTag, resetTag))
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
    ui.rawView.SetText(sb.String())
    ui.rawView.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
        if event.Key() == tcell.KeyEscape {
            ui.pages.SwitchToPage("packets")
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
    title := fmt.Sprintf("Packets for %s:%d ↔ %s:%d", conn.SrcIP, conn.SrcPort, conn.DstIP, conn.DstPort)
    table.SetBorder(true).SetTitle(title)
    headers := []string{"Time", "Source", "Dest", "Proto", "Service", "Len"}
    for i, h := range headers {
        table.SetCell(0, i, tview.NewTableCell(h).
            SetTextColor(tcell.ColorYellow).
            SetSelectable(false))
    }
    row := 1
    for _, p := range packets {
        if (p.SrcIP.String() == conn.SrcIP.String() && p.SrcPort == conn.SrcPort && p.DstIP.String() == conn.DstIP.String() && p.DstPort == conn.DstPort) ||
           (p.SrcIP.String() == conn.DstIP.String() && p.SrcPort == conn.DstPort && p.DstIP.String() == conn.SrcIP.String() && p.DstPort == conn.SrcPort) {
            table.SetCell(row, 0, tview.NewTableCell(p.Timestamp.Format("15:04:05")))
            table.SetCell(row, 1, tview.NewTableCell(fmt.Sprintf("%s:%d", p.SrcIP, p.SrcPort)))
            table.SetCell(row, 2, tview.NewTableCell(fmt.Sprintf("%s:%d", p.DstIP, p.DstPort)))
            table.SetCell(row, 3, tview.NewTableCell(p.Protocol))
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

// colorTag returns a hex code suitable for tview dynamic color tags.
func colorTag(c tcell.Color) string {
    rgb := uint32(c)
    r := (rgb >> 16) & 0xff
    g := (rgb >> 8) & 0xff
    b := rgb & 0xff
    return fmt.Sprintf("#%02x%02x%02x", r, g, b)
}
